# Module Spec: Transparent UDP Original-Destination Resolution & Self-Loop Guard

## 1. Overview

本模块定义透明代理 UDP 入口（`ProxyHandler.serveTransparentUDP`）在两种重定向模式下，如何确定一个数据报的「原始目标地址」，以及如何在归属失败时安全地丢弃数据报，杜绝代理自环、日志风暴与错误目标转发。

背景（生产事故 2026-09-25，`oget` 经 eBPF 重定向下载 HuggingFace 模型）：

- eBPF 模式下，cgroup hook 在 `connect4/connect6/sendmsg4/sendmsg6` 里把目标地址改写成 `127.0.0.1:<TransPort>`，并把真实目标写入 `udp_orig_dst` map（key 仅 `{src_port, family}`），Go 侧每收到一个数据报就 `LookupAndDelete` 消费一次。
- `udp_orig_dst` 是「一个源端口一个槽位、读后即删」的语义，因此**只有突发中的第一个数据报能被正确归属**：quic-go 会复用同一个 UDP socket 承载多条 QUIC 连接（日志中 `127.0.0.1:43414` 同时发往 `160.16.86.14:443` 与 `18.155.68.14:443`），后续数据报必然查表失败。
- 查表失败时原实现回退到 `ReadFromUDPWithOrigDst` 的 cmsg，但 `StartTransparent()` 在 eBPF 模式下也使用带 `IP_RECVORIGDSTADDR` 的 `ListenUDPTransparent`；此时 cmsg 返回的是**已被改写后的**目的地址，即代理自身监听地址 `127.0.0.1:10080`（已实测验证）。
- 该错误目标被当作真实目标后：`dialTargetUDP(127.0.0.1:10080)` 打通、伪造源地址 socket `DialUDPTransparent(127.0.0.1:10080)` 绑定失败（`bind: address already in use`，与 `transUDPLn` 冲突），并写入一条指向自身的假 session。TCP 的 `forward()` 有 "Loop detected" 自环保护（`internal/handler.go:1393`），UDP 路径此前没有对应保护。

## 2. Interface / API Contract

### 2.1 目标解析（纯函数，可单测）

```go
// resolveUDPTarget 决定一个透明拦截到的 UDP 数据报的真实目标。
// ebpfMode 为 true 时，目标只能来自 eBPF udp_orig_dst map；
// cmsgDst 必须被忽略，因为它是重写后的代理监听地址。
// 返回 ok=false 表示该数据报必须被丢弃（不得 dial、不得建 session）。
func resolveUDPTarget(ebpfMode bool, cmsgDst, ebpfDst *net.UDPAddr, lookupErr error) (dst *net.UDPAddr, ok bool)
```

### 2.2 自环判定

```go
// isSelfProxyTarget 判断目标是否指回 vproxy 自身的透明代理监听地址。
func (ph *ProxyHandler) isSelfProxyTarget(dst *net.UDPAddr) bool
```

判定条件：`dst.Port == ph.TransPort` 且 `dst.IP.IsLoopback()`（eBPF 重写只会落到 `127.0.0.1`/`::1`；环回地址在 BPF hook 中已被 bypass，不可能作为真实目标出现，故对正常业务流量无误伤）。

### 2.3 诊断限流

```go
// udpDropLog 为丢弃诊断提供时间窗口限流，防止日志风暴。
type udpDropLog struct{ last atomic.Int64 }
func (l *udpDropLog) allow(now time.Time, interval time.Duration) bool
```

## 3. Acceptance Criteria (BDD)

### Feature 1: eBPF 模式下 UDP 目标必须来自 eBPF map

#### Scenario 1: [SPEC-UDP-001] 查表命中时采用 eBPF map 中的原始目标
- **Given** `ebpfMode == true`，cmsg 目标为 `127.0.0.1:10080`（重写后地址），`udp_orig_dst` 查到 `160.16.86.14:443`
- **When** 调用 `resolveUDPTarget`
- **Then** 返回 `160.16.86.14:443` 且 `ok == true`；cmsg 目标被完全忽略。
- **Mapped Test:** `internal/udp_guard_test.go:TestResolveUDPTarget_EBPFHitPrefersMap`

#### Scenario 2: [SPEC-UDP-002] 查表失败时丢弃数据报，不得回退到 cmsg
- **Given** `ebpfMode == true`，cmsg 目标为 `127.0.0.1:10080`，`udp_orig_dst` 查表返回错误
- **When** 调用 `resolveUDPTarget`
- **Then** 返回 `ok == false`，绝不把 `127.0.0.1:10080` 当成真实目标（禁止 dial 自身、禁止创建假 session）。
- **Mapped Test:** `internal/udp_guard_test.go:TestResolveUDPTarget_EBPFMissDrops`

#### Scenario 3: [SPEC-UDP-003] iptables TPROXY 模式保持原有 cmsg 语义
- **Given** `ebpfMode == false`，cmsg 目标为 `1.1.1.1:443`（TPROXY 保留真实目的地址）
- **When** 调用 `resolveUDPTarget`
- **Then** 返回 `1.1.1.1:443` 且 `ok == true`；若 cmsg 缺失（`nil`）则返回 `ok == false`。
- **Mapped Test:** `internal/udp_guard_test.go:TestResolveUDPTarget_IPTablesMode`

### Feature 2: 代理自环防护

#### Scenario 4: [SPEC-UDP-004] 目标等于自身透明代理监听地址时丢弃
- **Given** `ph.TransPort == 10080`
- **When** 判定 `127.0.0.1:10080` 或 `[::1]:10080`
- **Then** `isSelfProxyTarget` 返回 `true`。
- **Mapped Test:** `internal/udp_guard_test.go:TestIsSelfProxyTarget_LoopbackListener`

#### Scenario 5: [SPEC-UDP-005] 正常业务目标不受自环判定影响
- **Given** `ph.TransPort == 10080`
- **When** 判定 `8.8.8.8:10080`（远端恰好用同端口）、`127.0.0.1:8080`、`nil`
- **Then** `isSelfProxyTarget` 均返回 `false`，流量继续正常转发。
- **Mapped Test:** `internal/udp_guard_test.go:TestIsSelfProxyTarget_AllowsNormalTargets`

### Feature 3: 诊断日志限流

#### Scenario 6: [SPEC-UDP-006] 丢弃诊断在时间窗口内只输出一次
- **Given** 限流窗口为 1s 的 `udpDropLog`
- **When** 在 100ms 内连续调用 5 次 `allow`
- **Then** 仅第 1 次返回 `true`；窗口过期后再次返回 `true`。
- **Mapped Test:** `internal/udp_guard_test.go:TestUDPDropLog_Throttles`

## 4. 已知限制（不在本次止血范围内）

eBPF 模式下 `udp_orig_dst` 以 `{src_port, family}` 单槽位 + 读后即删，**多数据报突发（QUIC 常态）本质上无法逐报归属**。本次止血只保证「不再自环、不再错误转发到自身、不再刷 ERROR」；eBPF 模式下的 UDP/QUIC 代理流畅度属于后续根治议题（候选方案：不删表项 + 时效校验、或 eBPF 模式下不拦截 UDP 让 QUIC 直连回退 TCP），需另立 Spec 评审。
