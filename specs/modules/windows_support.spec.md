# Module Spec: Windows 平台稳定性与进程匹配

## 1. Overview
本模块定义 `vproxy` 在 Windows 操作系统下的生命周期管理（启动/停止与路由清理）、Wintun 驱动检查、以及基于 TCP/UDP 本地端口的进程路径解析契约。

## 2. Interface / API Contract
- **`tproxy.Cleanup()`**: 移除 Windows 注入的 `0.0.0.0/1` 与 `128.0.0.0/1` 路由，并释放 Wintun 句柄。
- **`tproxy.GetProcessNameByConn(conn interface{}) (string, int, error)`**: 支持从 TCP/UDP 连接中提取远程地址（应用端源端口），并在 Windows 系统内核表中反查对应的 PID 及可执行文件完整路径。
- **Windows TUN startup health**: `vproxy init` must not report success until the background server has completed Wintun/TUN initialization and routing setup; initialization errors must be surfaced and must not leave interception routes installed.
- **Windows TUN routing safety**: Wintun creation, gVisor stack setup, and both `/1` route additions are transactional. Any failure must remove routes, close the TUN device, and leave the host on its original route configuration.
- **Windows Native IP Helper & LUID Contract**: Adapter IP address assignment (`198.18.0.1/15`) and split-routing injection (`0.0.0.0/1`, `128.0.0.0/1`) MUST operate directly against the Wintun adapter's 64-bit `NET_LUID` via Windows IP Helper APIs (`iphlpapi.dll`), without executing external shells/binaries (`netsh.exe`, `powershell.exe`) or blocking on PnP adapter name discovery via `net.Interfaces()`.

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

### Feature: SOCKS5 proxy connectivity test utility

#### Scenario 5: [SPEC-SOCKS5-001] 独立验证 SOCKS5 代理链路
- **Given** a SOCKS5 endpoint in `socks5://host:port` format
- **When** the test utility is executed with an optional target URL and timeout
- **Then** it reports TCP reachability to the SOCKS5 endpoint, SOCKS5 CONNECT success, target HTTP status, elapsed time, and a bounded response snippet
- **And** it performs no TUN, route, adapter, or firewall changes
- **And** non-success in any stage returns a non-zero exit code
- **Mapped Test:** `tests/socks5/main.go` unit and command tests

### Feature: Windows TUN DNS and local upstream routing

#### Scenario 6: [SPEC-WIN-006] TUN DNS and local/private upstream bypass
- **Given** Windows transparent TUN mode is active
- **When** the Wintun interface is configured
- **Then** IPv4 DNS for the interface is set to the local TUN DNS endpoint `198.18.0.1`
- **And** vproxy outbound sockets skip physical-interface binding for loopback, private, and link-local destinations
- **And** connections to a local SOCKS5 upstream remain reachable without being redirected through the TUN
- **And** TUN startup fails transactionally if mandatory DNS configuration fails
- **Mapped Test:** Windows routing/DNS integration harness and SOCKS5 end-to-end verification

#### Scenario 7: [SPEC-WIN-007] Windows TUN uses a peer DNS address and L3 endpoint
- **Given** Windows Wintun exposes host address `198.18.0.1/15`
- **When** transparent TUN mode configures DNS and the gVisor link endpoint
- **Then** the Wintun DNS server is configured as peer address `198.18.0.2`, not the host address
- **And** the gVisor stack accepts `198.18.0.2/15` for DNS interception
- **And** the Wintun bridge uses an empty link address because Wintun is an L3 device
- **And** the Wintun IPv4 interface metric remains explicitly preferred
- **And** cleanup removes the peer address and restores the original DNS configuration
- **Mapped Test:** Windows explicit DNS query and TUN HTTPS integration harness

#### Scenario 8: [SPEC-WIN-008] Windows TUN preserves inbound TCP payloads
- **Given** a TCP connection is accepted by the Windows gVisor TUN stack
- **When** Wintun delivers an IPv4 or IPv6 packet to the userspace bridge
- **Then** the bridge does not claim checksum validation or hardware offload for that packet
- **And** gVisor validates inbound transport checksums before delivering payloads
- **And** a native `curl.exe` HTTPS request can exchange request and response payloads after the upstream tunnel is established
- **Mapped Test:** Windows TUN relay integration harness using `curl.exe -v`

#### Scenario 9: [SPEC-WIN-009] Windows TUN avoids upstream routing loops
- **Given** transparent TUN mode installs the two `/1` interception routes
- **When** vproxy uses an upstream endpoint whose host is not loopback, private, or link-local
- **Then** startup resolves the upstream endpoint address and installs a more-specific host route through the pre-existing physical interface
- **And** cleanup removes only the host routes created by vproxy
- **And** vproxy logs a clear diagnostic when a loopback upstream delegates internet dialing to another process whose sockets cannot inherit vproxy's physical-interface binding
- **Mapped Test:** Windows routing harness with a resolved remote upstream and local SOCKS5 loop-deadlock diagnostic

#### Scenario 10: [SPEC-WIN-010] Configurable node bypass routes and process-level direct relay
- **Given** transparent TUN mode intercepts system-wide traffic via `/1` routes
- **When** the upstream proxy is a local loopback relay (`socks5://127.0.0.1:1080`) whose actual remote nodes cannot be inferred automatically
- **Then** vproxy supports a `bypass_nodes` configuration list containing remote node IPs, CIDRs, or hostnames
- **And** Windows TUN startup installs `/32` physical interface bypass routes for all entries in `bypass_nodes` and cleans them up upon exit
- **And** intercepted connections whose originating process/PID matches the local upstream listener (or a `PROCESS,<name>,DIRECT` rule) are dialed directly via `ph.dialDirect` through the physical interface
- **And** forwarded non-FakeIP connections without a Windows host PID (such as from WSL2/Hyper-V virtual interfaces) are dialed directly via `ph.dialDirect` through the physical interface to prevent loop deadlocks
- **Mapped Test:** Windows node bypass routing harness and local relay loop prevention test

### Feature: 原生 IP Helper API 与 LUID 驱动适配

#### Scenario 5: [SPEC-WIN-005] 通过 LUID 与 IP Helper API 原生配置网络与路由
- **Given** Wintun 适配器创建成功并获得 64 位 `NET_LUID`
- **When** 触发 Windows TUN 网络配置
- **Then** 代码必须直接调用 `iphlpapi.dll`（如 `CreateUnicastIpAddressEntry`、`CreateIpForwardEntry2`）绑定 IP `198.18.0.1/15` 及下发 `/1` 路由，严禁派生 `powershell.exe` 或 `netsh.exe` 进程，且在适配器关闭时通过事务性回滚保障宿主机网络还原
- **Mapped Test:** `proxy/tproxy/routing_windows_test.go:TestWindows_LUIDRouteSetup`
