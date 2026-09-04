# Module Spec: Windows 平台稳定性与进程匹配

## 1. Overview
本模块定义 `vproxy` 在 Windows 操作系统下的生命周期管理（启动/停止与路由清理）、Wintun 驱动检查、以及基于 TCP/UDP 本地端口的进程路径解析契约。

## 2. Interface / API Contract
- **`tproxy.Cleanup()`**: 移除 Windows 注入的 `0.0.0.0/1` 与 `128.0.0.0/1` 路由，并释放 Wintun 句柄。
- **`tproxy.GetProcessNameByConn(conn interface{}) (string, int, error)`**: 支持从 TCP/UDP 连接中提取远程地址（应用端源端口），并在 Windows 系统内核表中反查对应的 PID 及可执行文件完整路径。
- **Windows TUN startup health**: `vproxy init` must not report success until the background server has completed Wintun/TUN initialization and routing setup; initialization errors must be surfaced and must not leave interception routes installed.
- **Windows TUN routing safety**: Wintun creation, gVisor stack setup, and both `/1` route additions are transactional. Any failure must remove routes, close the TUN device, and leave the host on its original route configuration.

## 3. Acceptance Criteria (BDD)

### Feature: Windows 守护进程停止与网络恢复

#### Scenario 1: [SPEC-WIN-001] 正常停止守护进程并清理路由
- **Given** Windows 守护进程已启动，系统路由表中存在指向 Wintun 的 `0.0.0.0/1` 与 `128.0.0.0/1`
- **When** 用户在命令行执行 `vproxy stop`
- **Then** 守护进程被终止，且残余的 `/1` 路由被全部删除，恢复系统原有直连网络
- **Mapped Test:** `proxy/tproxy/process_windows_test.go:TestWindows_CleanupRoutes`

### Feature: UDP 进程路径识别

#### Scenario 2: [SPEC-WIN-002] 通过 UDP 源端口反查进程 PID 与路径
- **Given** 本地应用程序正在监听或使用 UDP 端口发送报文
- **When** 调用 `GetProcessNameByConn` 传入 `*net.UDPAddr`
- **Then** 正确通过 `GetExtendedUdpTable` 查询到对应进程的 PID 并提取出可执行文件路径
- **Mapped Test:** `proxy/tproxy/process_windows_test.go:TestWindows_GetProcessNameByUDPPort`

### Feature: Windows TUN startup failure handling

#### Scenario 3: [SPEC-WIN-003] TUN 初始化失败不得伪装为成功
- **Given** Wintun is unavailable, incompatible, or fails while creating the adapter or configuring routes
- **When** the user runs `vproxy init`
- **Then** `init` reports a failure or startup timeout, the failure is logged with the underlying cause, and no `/1` interception routes remain installed
- **Mapped Test:** `cmd/vproxy` startup-health tests and `proxy/tproxy` routing rollback tests

#### Scenario 4: [SPEC-WIN-004] TUN 初始化成功后才允许流量验证
- **Given** Wintun and the gVisor stack are initialized successfully
- **When** `vproxy init` returns success
- **Then** the daemon is ready to accept intercepted traffic and the caller may run the required timed DNS, TCP/443, and HTTPS checks followed by mandatory `vproxy clean`
- **Mapped Test:** Windows integration harness
