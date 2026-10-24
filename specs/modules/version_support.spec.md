# Module Spec: Version Support & Dynamic VCS Commit Resolution

## 1. Overview
本模块定义了 `vproxy` 的版本号规范与解析机制：
1. **默认使用 VCS Commit ID**：在无显式 `-ldflags` 注入时，自动利用 Go 运行时内置的 `runtime/debug.ReadBuildInfo()` 动态提取构建时的 Git Commit Revision (`vcs.revision`) 与改动标记 (`vcs.modified`) 作为默认版本标识，确保任何通过原生 `go build` 或 `go install` 构建的二进制均自带可溯源的版本号。
2. **支持编译期构建注入重载**：支持在 CI/CD 或 Taskfile 构建脚本中通过 `-ldflags "-X github.com/qtopie/vproxy/internal.Version=..."` 或 `-X ...GitCommit=...` 注入语义化发布版本（如 `v1.0.9`）。
3. **版本查看入口**：
   - 独立子命令：`vproxy version` 输出格式化的详细版本、Git Commit、构建时间、Go 编译器版本与平台架构信息。
   - CLI 选项：`vproxy -version`、`vproxy --version`、`vproxy -V`。
4. **单点真实源 (SSOT) 同步**：
   - 统一替换 `internal/ipc/server_linux.go` 中硬编码的 `"1.0.0"`，使 `vproxy status` 显示真实运行中服务的版本号。
   - 统一替换 `internal/otel.go` 中硬编码的 `service.version: "1.0.7"`，使链路追踪（OpenTelemetry Tracing）元数据与二进制版本精确一致。

---

## 2. Interface / API Contract

### 2.1 Package `internal` Version API (`internal/version.go`)
```go
package internal

// Injected via -ldflags during release builds (optional)
var (
    Version   = ""
    GitCommit = ""
    BuildDate = ""
)

type VersionInfo struct {
    Version   string `json:"version"`
    GitCommit string `json:"git_commit"`
    GitDirty  bool   `json:"git_dirty"`
    BuildDate string `json:"build_date,omitempty"`
    GoVersion string `json:"go_version"`
    Platform  string `json:"platform"`
}

// GetVersion returns the canonical version string (e.g. "v1.0.9", or short commit "26e5bdc", or "26e5bdc-dirty").
func GetVersion() string

// GetVersionInfo returns complete structured version metadata.
func GetVersionInfo() VersionInfo
```

### 2.2 CLI Commands and Flags (`cmd/vproxy`)
- 子命令 `vproxy version`：
  ```text
  vproxy version 26e5bdc (commit: 26e5bdc570f0dad566f4c792c5830c681eb5a618, dirty: true, go: go1.26.0, linux/amd64)
  ```
- 命令行标志：`-version` / `--version` / `-V` 输出简要或详细版本并立即退出（Exit Code 0）。

### 2.3 IPC & Tracing Metadata Integration
- `internal/ipc/server_linux.go`:
  ```go
  StatusResponse{
      Version: internal.GetVersion(),
      Uptime:  ...,
  }
  ```
- `internal/otel.go`:
  ```go
  attribute.String("service.version", internal.GetVersion())
  ```

---

## 3. Acceptance Criteria (BDD)

### Feature 1: Dynamic VCS Commit Extraction

#### Scenario 1: [SPEC-VER-001] 无 ldflags 时自动降级使用 runtime/debug vcs.revision
- **Given** 二进制未注入 `internal.Version`，但由 git 仓库工作区执行 `go build`
- **When** 调用 `internal.GetVersion()`
- **Then** 返回非空且匹配当前 git commit 的短哈希（若有未提交改动则追加 `-dirty` 后缀），不返回 `"unknown"`。
- **Mapped Test:** `internal/version_test.go:TestGetVersion_VCSResolution`

#### Scenario 2: [SPEC-VER-002] 显式注入 Version 时优先采用注入值
- **Given** `internal.Version` 赋值为 `"v1.2.0"`
- **When** 调用 `internal.GetVersion()`
- **Then** 返回 `"v1.2.0"`。
- **Mapped Test:** `internal/version_test.go:TestGetVersion_ExplicitPriority`

### Feature 2: CLI Version Entrypoints

#### Scenario 3: [SPEC-VER-003] `vproxy version` 子命令输出版本并退出
- **When** 执行 `vproxy version`
- **Then** 进程打印包含 commit、go 版本、平台的版本信息，以 exit code 0 退出。
- **Mapped Test:** `cmd/vproxy/version_test.go:TestVersionCommand`

#### Scenario 4: [SPEC-VER-004] `-version` 与 `--version` 标志支持
- **When** 执行 `vproxy -version` 或 `vproxy --version`
- **Then** 打印版本并以 exit code 0 退出，不启动代理服务也不报 flag 错误。

### Feature 3: IPC & OpenTelemetry Synchronization

#### Scenario 5: [SPEC-VER-005] IPC 状态查询响应返回当前真实版本
- **Given** 后台运行守护进程
- **When** 发送 IPC `RequestStatus()` 请求
- **Then** `resp.Version` 等于 `internal.GetVersion()`，非硬编码的 `"1.0.0"`。
