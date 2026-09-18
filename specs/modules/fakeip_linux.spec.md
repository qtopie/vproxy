# Module Spec: Linux Fake-IP 与 DNS 劫持拦截引擎 (FakeIP Linux)

## 1. Overview
本模块定义 `vproxy` 在 Linux 环境下的 Fake-IP 域名拦截与 DNS 劫持分流引擎（`FakeIP Linux`，SPEC-FAKEIP-LINUX-001 ~ SPEC-FAKEIP-LINUX-006）。

### 目标与痛点解决
在 Linux 透明代理（eBPF cgroup 与 TUN/GVisor）环境下：
1. **解决裸 IP 规则脱靶**：客户端发出连接时若先走本地 DNS，传入 vproxy 的目标为裸 IP（如 `172.217.114.4:443`），在 `FINAL,DIRECT` 策略下无法命中 `google.com,PROXY` 这类域名规则，导致 GFW 阻断及 15.2s 超时；
2. **解决 DNS 投毒与污染**：在 DNS 查询阶段直接返回保留地址池（`198.18.0.0/15`）中的合成 Fake-IP，阻止被投毒的 DNS 污染操作系统 DNS 缓存；
3. **确定性域名还原**：将 TCP/UDP 流量的目标从 `198.18.x.x` 无损还原回真实域名，交由规则引擎匹配，并经由上游 SOCKS5 远端解析。

---

## 2. Interface / Behavioral Contracts

### 2.1 Fake-IP 地址池生命周期
- **保留网段**：RFC 5737 规定的测试与保留网段 `198.18.0.0/15`。
- **全局单例**：由 `dns.InitGlobalPool("198.18.0.0/15")` 初始化。
- **映射管理**：
  - `GetIP(domain string) net.IP`：正向映射（Domain -> Fake-IP）。
  - `GetDomain(ip net.IP) string`：反向还原（Fake-IP -> Domain）。
  - `IsFakeIP(ip net.IP) bool`：判断目标 IP 是否属于 `198.18.0.0/15`。

### 2.2 DNS 劫持与响应契约
- **监听与劫持**：
  - **TUN 模式 (`StartLinuxTransparent`)**：GVisor 用户态协议栈在 UDP Forwarder 中劫持目标端口为 53 的 DNS 请求。
  - **TPROXY / UDP 模式 (`serveTransparentUDP`)**：透明 UDP 监听层捕获目标端口为 53 的数据报文。
- **查询处理与应答**：
  - 解析客户端发送的 DNS Query（支持 Type A 与 Type AAAA）。
  - Type A（IPv4）：生成合法的 DNS 应答包（Flags: 0x8180 Standard query response, No error），Answer 区域写入对应的 `198.18.x.x`，TTL 设为 60s。
  - Type AAAA（IPv6）：返回空的 NOERROR 应答（ANCOUNT = 0），防止双栈客户端因 IPv6 优先走直连导致泄漏或回退。
  - 使用 Linux 内核透明套接字（`IP_TRANSPARENT`）通过 `tproxy.DialUDPTransparent(dst)` 以原始 DNS 服务器的身份（Spoofed Source IP:Port）将应答回写给客户端，客户端透明无感知。

### 2.3 传输层连接还原与规则匹配契约
- 当客户端发起 TCP 连接（如发往 `198.18.0.123:443`）或 UDP 数据报时：
  1. `ProxyHandler.forward(conn, target)` 与 `handleUDP(ctx, local, target)` 检测 `dns.GlobalPool.IsFakeIP(host)`；
  2. 若为 Fake-IP，反查 `domain = dns.GlobalPool.GetDomain(ip)`，将 `target` 替换为 `domain:port`；
  3. 规则管理器（`RuleManager.MatchContext`）以真实 `domain` 执行分流比对；
  4. 命中 `PROXY` 时：经由 SOCKS5 上游建立连接，向 SOCKS5 传递 FQDN 域名，由远端代理执行安全解析；
  5. 命中 `DIRECT` 时（如国内直连域名分流）：`dialDirect` 检测到目标为 Fake-IP 时，使用配置的直接 DNS（如 `223.5.5.5:53`）在本地发起真实解析获取公网物理 IP，再建立直连连接（SPEC-WIN-012 契约在 Linux 对等实现）。

---

## 3. Acceptance Criteria (BDD)

### Feature: Linux Fake-IP 初始化与生命周期

#### Scenario 1: [SPEC-FAKEIP-LINUX-001] Linux 启动阶段全局 Fake-IP 池就绪
- **Given** vproxy 在 Linux 平台上启动（无论 TUN 模式还是 TPROXY/eBPF 模式）
- **When** 服务完成初始化
- **Then** `dns.GlobalPool` 不为 `nil`
- **And** `dns.GlobalPool.IsFakeIP(net.ParseIP("198.18.0.10"))` 返回 `true`
- **And** `dns.GlobalPool.IsFakeIP(net.ParseIP("172.217.114.4"))` 返回 `false`

---

### Feature: Linux DNS 查询拦截与 Fake-IP 应答

#### Scenario 2: [SPEC-FAKEIP-LINUX-002] A 记录拦截并返回 198.18.x.x
- **Given** 客户端针对 `www.google.com` 构造标准 DNS Type A 查询包
- **When** DNS 拦截器接收并调用 `dns.HandleDNSQuery` 处理
- **Then** 返回合法 DNS 应答报文，错误码为 NOERROR
- **And** Answer 记录中的 IP 属于 `198.18.0.0/15`
- **And** 反向查验 `dns.GlobalPool.GetDomain(ip)` 得到 `www.google.com`

#### Scenario 3: [SPEC-FAKEIP-LINUX-003] AAAA 记录返回空 NOERROR 避免 IPv6 泄漏
- **Given** 客户端针对 `www.google.com` 构造标准 DNS Type AAAA 查询包
- **When** DNS 拦截器接收并调用 `dns.HandleDNSQuery` 处理
- **Then** 返回标准应答，ANCOUNT 为 0，RCODE 为 0 (NOERROR)

---

### Feature: 传输层 Fake-IP 还原与规则匹配

#### Scenario 4: [SPEC-FAKEIP-LINUX-004] 传输层目标透明还原
- **Given** `dns.GlobalPool` 中存在映射 `198.18.0.5 -> www.google.com`
- **When** 收到进入透明代理的连接，目标为 `198.18.0.5:443`
- **Then** `target` 变量在规则匹配前被重写为 `www.google.com:443`
- **And** 规则引擎匹配 `google.com,PROXY` 成功命中 `ActionProxy`
- **And** 即使配置为 `FINAL,DIRECT`，连接也不会落入默认直连超时

#### Scenario 5: [SPEC-FAKEIP-LINUX-005] DIRECT 策略下的真实物理 IP 回退解析
- **Given** `dns.GlobalPool` 中存在映射 `198.18.0.6 -> cn.bing.com`
- **And** 规则引擎判定 `cn.bing.com` 为 `ActionDirect`
- **When** 调用 `dialDirect("198.18.0.6:443")`
- **Then** `dialDirect` 检测到该 Fake-IP 并获取真实域名 `cn.bing.com`
- **And** 使用直接 DNS 解析 `cn.bing.com` 获得真实公网 IP 并完成物理拨号

---

### Feature: vproxy agy 派生与后续子进程代理继承

#### Scenario 6: [SPEC-FAKEIP-LINUX-006] vproxy agy 启动时自动注入代理环境变量与 cgroup 继承
- **Given** 用户通过 `vproxy agy` 启动命令包装器
- **When** wrapper 完成 cgroup 迁移并构造待执行进程环境
- **Then** `agy` 进程及其所有派生子进程保持在 `/sys/fs/cgroup/vproxy` cgroup 中
- **And** 进程环境变量中自动注入 `http_proxy`, `https_proxy`, `all_proxy`, `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`
- **And** 后续在 `agy` 中派生执行的子进程（如 `curl`, `git`, `npm`, 脚本命令）自动走代理

