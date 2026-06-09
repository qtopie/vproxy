# macOS TUN & Fake-IP Network Design Plan

## Objective
解决 macOS TUN 网络在第三层（IP层）拦截时丢失原始域名的问题。此方案通过在现有的 gVisor 用户态协议栈中引入 Fake-IP（虚拟 IP）状态机，来拦截本地 DNS 查询并分配映射。从而在流量进入用户态协议栈时，能够将其还原回真实域名，交由规则引擎实现精准的按域名分流。

## Current State Analysis
- **入站流量捕获 (Inbound Capture):** macOS 的 TUN 接口 (`utun`) 已在 `proxy/tproxy/tproxy_darwin.go` 中实现全局路由劫持。
- **用户态协议栈 (Netstack):** gVisor (`tcpip/stack`) 已经接入，可以接管 TUN 过来的 TCP/UDP 报文并将其终结为 Go 的 `net.Conn`。
- **出站防环路 (Anti-Loop):** macOS 已利用 `IP_BOUND_IF` (socket option `0x19`) 绑定代理发出的 Socket 到真实物理网卡，防止了路由环路。
- **缺失的环节 (The Problem):** 应用程序在发包前已将域名解析为 IP，导致 gVisor 提取出来的目的地址全是 IP。因为缺乏原始域名信息，`vproxy` 现有的 `DOMAIN` 或 `DOMAIN-SUFFIX` 等分流规则无法生效。

## Proposed Architecture

### 1. DNS 拦截与 Fake-IP 分配
- **DNS 监听器:** 在 `vproxy` 内部基于 TUN 拦截发往端口 `53` 的 UDP/TCP DNS 报文。
- **Fake-IP 资源池:** 定义一个专用的 Fake-IP 网段 (如 `198.18.0.0/16`，这是 RFC 2544 保留用于测试的网段，常作此用)。
- **状态机流转:** 
  - 当应用程序发出域名查询 (如 `google.com`) 并流入 TUN 被拦截时。
  - DNS 拦截器从 Fake-IP 资源池中分配一个 IP (例如 `198.18.0.5`)，并在内存 (如 Concurrent Map 或 LRU Cache) 中建立映射：`198.18.0.5 -> google.com`。
  - 拦截器直接组装合法的 DNS 响应包（包含该 Fake-IP）返回给应用程序，应用层以为获取到了真实的 IP。

### 2. 连接处理与域名还原 (Domain Restoration)
- 应用程序随即向被分配的 Fake-IP (`198.18.0.5`) 发起 TCP 握手或 UDP 发包，流量再次流入 TUN 并被 gVisor 处理。
- gVisor 将终结的 `net.Conn` 移交给 `internal/handler.go` 中的 `tcpHandler` / `udpHandler`。
- **反查域名:** 处理器检查目标 IP，若命中 Fake-IP 网段，则去映射表中反查得到原始域名 `google.com`。
- **上下文替换:** 在代理逻辑的上下文中，将原本的目的 IP 替换回真实的域名。

### 3. 规则引擎匹配与真实 DNS 解析
- 携带了原始域名 (`google.com`) 的请求被送入 `Router` (`internal/router.go`) 进行判定。
- **域名规则:** Router 可以完美命中 `DOMAIN`、`DOMAIN-SUFFIX` 和进程等相关规则。
- **真实 IP 的延迟解析:** 
  - 如果匹配到的是 `PROXY` (走代理)，直接把域名交由上游代理节点解析即可，实现了远端解析，防止本地 DNS 污染。
  - 如果匹配到需要验证 IP 的规则 (如 `IP-CIDR`, `GEOIP`)，或者判定为 `DIRECT` (直连)，`vproxy` 此时才会在后台使用系统或配置的上游 DNS (DoH/DoT) 发起真实的 DNS 请求获取公网 IP，然后再将底层数据流转发过去。

### 4. 出站连接控制
- 当判断为 `DIRECT` 或与其他节点建立代理隧道时，`vproxy` 自己建立的出站连接将继续使用已有的 `GetDialerControl()` 逻辑（即 `IP_BOUND_IF`）。
- 该机制会确保 `vproxy` 自己发起的高级 DNS 解析以及真实流量的出站 Socket，全部绕过 TUN 路由表，直接从物理网卡流出，避免环路死循环。

## Implementation Steps
1. **核心 DNS / Fake-IP 模块 (`internal/dns`):**
   - 实现极简的 DNS 报文解析与构建器（或者引入现有轻量级 DNS 库）。
   - 实现 `FakeIPPool` 地址分配器和线程安全的映射表，包含 TTL 过期清理机制。
2. **TUN DNS 拦截 (`proxy/tproxy/tproxy_darwin.go`):**
   - 修改 gVisor 的 UDP/TCP forwarder 逻辑，将目的端口为 53 的流量剥离出来，转交到上述内部 DNS 模块进行响应。
3. **域名还原上下文 (`internal/handler.go`):**
   - 拦截并检查进来的连接目的地址。
   - 如果是 Fake-IP 网段，利用映射表将其替换为真正的域名字符串。
4. **Router 和直连强化 (`internal/router.go` & 出站逻辑):**
   - 确保路由分流依据还原后的域名。
   - 为 `DIRECT` 直连目标为域名的场景，加入安全的、防环路的出站 DNS 解析。

## 测试保证
- 实现后，必须运行 `make test-network`，以及执行后续的集成测试 (`bin/test_ebpf`, `bin/test_tproxy`, `bin/test_google`)。
- 保证全部通过，以验证 TUN/Fake-IP 的修改不破坏已有架构和数据流转。