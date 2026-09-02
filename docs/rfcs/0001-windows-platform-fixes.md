# RFC-0001: Windows 平台可用性与稳定性修复方案

- **Status:** Under Review
- **Author:** Antigravity Agent
- **Created Date:** 2026-09-02

## 1. Summary
本 RFC 针对 `vproxy` 在 Windows 操作系统下的核心缺陷与稳定性问题提出修复方案，重点解决执行 `vproxy stop` 导致的系统残留断网问题、UDP 协议下的进程级（PROCESS）规则匹配缺失，以及 `wintun.dll` 驱动缺失检测与引导。

## 2. Motivation
1. **停止守护进程导致系统断网**：当前 Windows 停止后台服务使用 `process.Kill()`，未能清理注入的 `0.0.0.0/1` 与 `128.0.0.0/1` 路由，造成网络黑洞。
2. **UDP 进程识别缺失**：`GetProcessNameByConn` 目前仅通过 `GetExtendedTcpTable` 查表，对于 UDP 数据报文无法识别发送端进程路径，导致基于 PROCESS 的 UDP 路由规则失效。
3. **驱动缺失引导不佳**：缺少 `wintun.dll` 时直接报错，缺乏对驱动存在性检测与用户指引。

## 3. Detailed Design

### 3.1 路由自动清理保证 (`cmd/vproxy/main.go` & `proxy/tproxy/tproxy_windows.go`)
- 在 `cmd/vproxy/main.go` 中，`stop` 命令分支执行 `stopBackgroundServer()` 后立即调用 `tproxy.Cleanup()`。
- 在 `stopBackgroundServer()` 内部增加操作系统级兜底清理，确保无论主进程如何退出，均会移除 `0.0.0.0/1` 与 `128.0.0.0/1` 路由。

### 3.2 增加 UDP 进程表查询 (`proxy/tproxy/process_windows.go`)
- 从 `iphlpapi.dll` 动态加载 `GetExtendedUdpTable`。
- 定义 `mibUDPRowOwnerPID` 结构体：
  ```go
  type mibUDPRowOwnerPID struct {
      LocalAddr uint32
      LocalPort uint32
      OwningPID uint32
  }
  ```
- 实现 `getPidByUDPPort(port int) (int, error)`，采用循环探测缓冲区机制避免 TOCTOU。
- `GetProcessNameByConn` 对 `*net.TCPAddr` 调用 `getPidByTCPPort`，对 `*net.UDPAddr` 调用 `getPidByUDPPort`。

### 3.3 驱动存在性前置检查 (`proxy/tproxy/tproxy_windows.go`)
- 启动 Wintun 前优先检测工作目录与系统目录是否存在 `wintun.dll`。若缺失，提供明确且友好的指引错误。

## 4. Alternatives Considered
- **使用 Windows 服务（Windows Service）托管**：需要额外的注册表与服务安装流程，对于轻量 CLI 工具复杂度过高，暂不引入。

## 5. Security & Performance Considerations
- 保持零 CGO 交叉编译支持。
- `GetExtendedUdpTable` 在有匹配端口时立即返回，对高频 UDP 查询影响微小。
