# Module Spec: Multi-NIC Routing & Dynamic Egress Interface Selection (Windows)

## 1. Overview
在 Windows 平台透明代理（Wintun TUN）环境下，针对多物理网卡（如以太网 + Wi-Fi）、虚拟网卡（Hyper-V / WSL2 / VMware）以及不同局域网子网共存的多网卡环境，重构出站 Socket 绑定与防环路绕行机制：
1. **动态出接口解析（Dynamic Egress Resolution）**：
   - 废除将所有出站 Socket 静态绑死到单一启动时物理网卡索引的旧逻辑。
   - 在 `GetDialerControl()` 拦截每次出站连接时，根据目标目的地址（IPv4 / IPv6），调用 Windows 底层路由决策 API（`iphlpapi!GetBestInterface` / `GetBestInterfaceEx`），动态获取送达该目的地址的最佳物理接口索引。
   - 避免将发往第二张网卡（如 `192.168.31.x`）的流量错误从第一张网卡（如 `192.168.1.x`）抛出导致的 `i/o timeout`。
2. **多网卡感知上游绕行路由（Multi-NIC Upstream Bypass Routing）**：
   - 废弃向单一物理网关强行注入整段 `192.168.0.0/16` / `10.0.0.0/8` 的做法，避免覆盖破坏第二张网卡的原生直连子网（On-link route）。
   - 针对用户配置的各 `upstreams` 与 `bypass_nodes`，根据其各自目的 IP 动态查询对应物理接口及其下一跳网关，精准注入各自所属网卡的 `/32` 主机绕行路由。
3. **出接口查询轻量缓存（TTL Cache）**：
   - 为目的地 IP 到最佳接口索引的映射维护短期线程安全缓存（如 5 秒 TTL），兼顾多网卡动态热拔插感知与高频拨号的高性能。

## 2. Interface / API Contract

### 2.1 Internal APIs (`proxy/tproxy`)
- `getBestInterfaceForTarget(targetIP net.IP) (int, error)`:
  - 输入：目标 IPv4/IPv6 地址。
  - 输出：送达该目标的最优物理接口索引（排除 Wintun TUN 自身）。
  - 错误处理：若查询失败或返回 Wintun 接口，回退至全局默认物理主网卡接口。
- `GetDialerControl()`:
  - 动态为各 outbound socket 执行 `IP_UNICAST_IF`（IPv4 网络字节序）及 `IPV6_UNICAST_IF`（IPv6 主机字节序），绑定对应 target 的最佳物理接口。
- `setupUpstreamBypassRoutes(tunLUID, upstreams, bypassNodes)`:
  - 对每个 upstream 和 bypass node 目标 IP，匹配其对应的物理出口网卡和有效下一跳（NextHop），安装针对性的主机/网段绕行路由。

---

## 3. Acceptance Criteria (BDD)

### Feature 1: Dynamic Egress Interface Selection

#### Scenario 1: [SPEC-WIN-NIC-001] 根据目的 IP 动态解析出接口
- **Given** Windows 拥有多张物理/虚拟网卡（网卡 A: `192.168.1.0/24`, 网卡 B: `192.168.31.0/24`）
- **When** 请求目的地址分别为 `192.168.1.100` 与 `192.168.31.253`
- **Then** `getBestInterfaceForTarget` 分别准确返回对应网卡 A 与网卡 B 的接口索引，且均不为 Wintun 网卡。
- **Mapped Test:** `proxy/tproxy/routing_windows_test.go:TestGetBestInterfaceForTarget`

#### Scenario 2: [SPEC-WIN-NIC-002] 出站 Socket 动态绑定到目标所属网卡
- **Given** 配置的上游节点位于副网卡网段（如 `socks5://192.168.31.253:1080`）
- **When** `vproxy` 出站连接向该上游节点建立 TCP 握手
- **Then** `GetDialerControl` 通过 `IP_UNICAST_IF` 绑定的接口为副网卡索引，数据包从正确的网卡发出，握手成功不超时。
- **Mapped Test:** `proxy/tproxy/routing_windows_test.go:TestDialerControlDynamicBinding`

### Feature 2: Multi-NIC Bypass Routes

#### Scenario 3: [SPEC-WIN-NIC-003] 上游绕行路由注入至正确的物理接口
- **Given** 配置了位于不同物理接口的上游代理地址
- **When** 调用 `setupUpstreamBypassRoutes` 安装绕行路由
- **Then** 各上游 `/32` 主机路由的 `InterfaceLUID` 与 `NextHop` 分别指向其自身可达的物理网卡及其网关，不将跨网段上游误绑定至主网卡网关。
- **Mapped Test:** `proxy/tproxy/routing_windows_test.go:TestMultiNICUpstreamBypassRoutes`

#### Scenario 4: [SPEC-WIN-NIC-004] 避免宽泛的大私网段路由破坏多网卡子网
- **Given** 启用了 Windows Wintun 透明代理
- **When** 路由初始化完成
- **Then** 不存在将整个 `192.168.0.0/16` 粗暴写死到单一网关的抢占式路由，各物理网卡的直连子网路由保持生效。
- **Mapped Test:** `proxy/tproxy/routing_windows_test.go:TestPreserveLocalSubnetRoutes`
