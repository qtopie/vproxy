# Windows TUN & Wintun Network Design Plan

## Objective
在 Windows 平台上实现高性能、无感的透明代理。利用 **Wintun** 驱动进行三层流量捕获，配合 **Fake-IP** 状态机还原域名，并使用 **IP_UNICAST_IF** 或 **WFP** 机制解决路由环路问题。

## Architecture Overview

### 1. 入流量捕获 (Inbound Capture): Wintun
- **Wintun 驱动**: 采用 WireGuard 团队开发的 Wintun 驱动，直接在内核层处理三层 (IP) 数据包，规避了传统 TAP 驱动的二层封装开销。
- **全局劫持**: 
  - 启动 Wintun 接口并分配 IP (如 `198.18.0.1`)。
  - 通过注入两条 `/1` 路由 (`0.0.0.0/1` 和 `128.0.0.0/1`)，其优先级高于默认的 `/0` 路由，从而将系统全局流量导向 Wintun 接口。

### 2. 用户态协议栈 (Netstack): gVisor
- 与 macOS 一致，使用 **gVisor** 的 `tcpip/stack` 接管 Wintun 涌入的原始 IP 报文。
- 将拦截到的 TCP/UDP 流量终结并抽象为 Go 原生的 `net.Conn` 对象。

### 3. DNS 拦截与 Fake-IP 状态机
- **DNS 劫持**: 拦截发往 `53` 端口的 UDP 流量，转交给内部 DNS 模块。
- **Fake-IP 分配**: 为 DNS 查询返回 `198.18.0.0/15` 网段内的虚拟 IP。
- **域名还原**: 在 `internal/handler.go` 中，根据目的 IP 反查映射表，将流量还原为原始域名，供规则引擎 (`internal/router.go`) 进行 `DOMAIN` 匹配。

### 4. 出站防环路 (Anti-Loop)
为了防止 `vproxy` 自身发出的代理流量再次掉进 Wintun 导致死循环，Windows 提供了以下机制：

- **方案 A: 接口绑定 (IP_UNICAST_IF)**
  - 利用 Windows `ws2_32.dll` 中的 `IP_UNICAST_IF` (socket option `31`)。
  - 在 `GetDialerControl()` 中，将所有出站 Socket 强制绑定到真实的物理网卡索引（Interface Index）。这样产生的流量会无视 Wintun 路由，直接从物理链路发出。
- **方案 B: 动态明细路由**
  - 在解析出远端代理服务器 IP 后，自动添加一条 `/32` 的具体路由指向物理网关。
- **方案 C: WFP (Windows Filtering Platform)**
  - 利用 Windows 过滤平台，在内核驱动层根据 PID 豁免 `vproxy` 进程的流量。

### 5. 进程匹配 (PROCESS-NAME)
- **原理**: 当流量进入 gVisor 时，根据源端口调用 `iphlpapi.dll` 的 `GetExtendedTcpTable` / `GetExtendedUdpTable`。
- **实现**: 实时获取连接对应的 PID，再通过 `OpenProcess` 拿到可执行文件路径（如 `chrome.exe`），实现按应用分流。

## Implementation Details (Go)
- **驱动调用**: 使用 `golang.zx2c4.com/wireguard/tun` 库。
- **DLL 链接**: 通过 `syscall.NewLazyDLL` 调用 `iphlpapi.dll` 和 `ws2_32.dll`。
- **权限要求**: 运行 `vproxy` 需要管理员 (Administrator) 权限以创建 Wintun 接口和修改路由表。

## 测试与验证
- 验证 Wintun 设备成功创建。
- 使用 `nslookup google.com` 确认返回 Fake-IP。
- 确认 `curl` 流量在日志中显示正确的原始域名和进程名称。
- 检查 `vproxy` 自身连接是否正确绕过 TUN。
