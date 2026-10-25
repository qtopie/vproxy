# Module Spec: Daemon Pipe & IPC Resilience (SPEC-DAEMON-001 ~ SPEC-DAEMON-004)

## 1. Overview
本模块解决因后台守护进程管道断裂引发 Go 运行时 `SIGPIPE` 崩溃，以及非 root 用户命令包装器在守护进程热重启瞬态窗口抛出 `process migration failed` 的稳定性缺陷。

### 核心问题背景：
1. **死管道（Broken Pipe）导致守护进程被 SIGPIPE 杀死**：
   - `vproxy init` 通过 `exec.Command` 启动后台守护进程，将 `cmd.Stdout` 和 `cmd.Stderr` 赋值给父进程内部由 Go 运行时维护的 `RotatingWriter`（`io.Writer` 接口）。
   - Go 的 `os/exec` 为非 `*os.File` 的 `io.Writer` 创建匿名管道 `os.Pipe`，而 `vproxy init` 父进程拉起子进程后即刻退出，关闭管道读取端。
   - 子进程在遇到上游连接重置等网络错误时调用 `TraceErrorf`，`internal/log.go` 针对 `LevelError` 将错误镜像输出到 `os.Stderr`。向已断开读取端的管道写入触发内核 `EPIPE`，Go 运行时默认对 `os.Stderr` 的 `EPIPE` 抛出致命未捕获 `SIGPIPE` 信号，瞬间击毙守护进程。
2. **systemd 重启风暴与 IPC 穿透真空**：
   - 守护进程崩溃后，systemd 执行 `ExecStop=/usr/local/bin/vproxy clean`（清理 `/tmp/vproxy.sock` 与 `/tmp/vproxy.pid`），并在 `RestartSec=5` 秒后拉起新实例。
   - 在此 5 秒窗口内，任何非 root 用户执行 `vproxy agy`（或其他包装命令）均因找不到 IPC Socket 且无权写入 cgroup 而遭遇瞬时致命失败（`process migration failed`）。

---

## 2. Invariants & Contract

### INV-DAEMON-1: Daemon Standard I/O Decoupling (SPEC-DAEMON-001)
- 守护进程在 `startBackgroundServer` 启动时，`cmd.Stdout` 和 `cmd.Stderr` **必须** 指向独立的真实文件描述符（如 `/dev/null` 或预打开的独立日志句柄），**严禁** 赋值给依赖父进程生命周期的匿名管道/内存 `io.Writer`。
- 守护进程自身的日志由子进程内 `InitBackgroundLogging()` 自主初始化打开，与父进程完全脱钩。

### INV-DAEMON-2: Process Session Decoupling on Unix (SPEC-DAEMON-002)
- 在 Unix/Linux 平台上，`prepareDaemonCommand(cmd)` **必须** 设置 `cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}`，使子进程脱离父进程会话与进程组，避免收到父级终端/会话信号干扰。

### INV-DAEMON-3: Daemon Stderr Mirror Suppression (SPEC-DAEMON-003)
- 在守护进程运行模式（环境变量 `VP_BACKGROUND=1`）下，`internal/log.go` 中的 `output()` **严禁** 将 `LevelError` 镜像写入 `os.Stderr`。
- 所有日志应仅输出至配置的日志轮转写入器（`logOutput`）。
- 同时，向 `os.Stderr` 的写入必须做安全防护，不可使 `EPIPE` 或写入错误中断关键业务链路。

### INV-DAEMON-4: IPC Attach Retry Resilience (SPEC-DAEMON-004)
- 在非 root 用户执行命令（如 `vproxy agy`）时，若直接写入 cgroup 失败，调用 `ipc.RequestAttach` 遭遇连接失败时，必须在判定失败前进行至多 3 次带退避（如 100ms、200ms、400ms）的短暂重试。
- 仅当全部重试均告失败时，方可触发 SelfHeal 或判定 `process migration failed`。

---

## 3. Acceptance Criteria (BDD Scenarios)

### Scenario 1: Daemon Stdout/Stderr Decoupling without Broken Pipe
- **Given** 管理员通过 `sudo vproxy init` 启动后台守护进程。
- **When** 父进程 `vproxy init` 退出返回控制台。
- **Then** 子进程的 `os.Stdout` 与 `os.Stderr` 保持有效连接（指向 `/dev/null` 或独立文件句柄），不会沦为由于父进程退出而关闭的死管道。
- **Mapped Test**: `cmd/vproxy/main_test.go:TestDaemonStdioDecoupling`

### Scenario 2: Unix Session Decoupling
- **Given** 在 Linux 操作系统上配置 daemon 命令。
- **When** 调用 `prepareDaemonCommand(cmd)`。
- **Then** `cmd.SysProcAttr.Setsid` 为 `true`。
- **Mapped Test**: `cmd/vproxy/privilege_unix_test.go:TestPrepareDaemonCommand_Setsid`

### Scenario 3: Log Stderr Mirror Suppression in Daemon Mode
- **Given** 进程处于守护模式（环境变量 `VP_BACKGROUND=1`）。
- **When** 发生网络错误记录 `TraceErrorf` 或 `Errorf`（`LevelError`）。
- **Then** 日志正常写入轮转日志文件，但不会向 `os.Stderr` 进行二次镜像输出。
- **Mapped Test**: `internal/log_test.go:TestLogOutput_SuppressStderrInDaemonMode`

### Scenario 4: IPC Attach Transient Retry in Wrappers
- **Given** 后台守护进程处于瞬时启动或重启中，Socket 首次连接返回失败。
- **When** 前台包装器调用带重试的 attach 逻辑，在第 2 次重试期间守护进程 socket 恢复就绪。
- **Then** 包装器成功完成 attach，避免瞬时 `process migration failed` 闪退。
- **Mapped Test**: `internal/ipc/client_test.go:TestRequestAttach_RetrySuccess`
