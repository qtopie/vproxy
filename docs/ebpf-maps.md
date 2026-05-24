# eBPF Maps 替代 iptables 方案

> **目标**：用 eBPF Maps 承接 iptables 当前承担的流量重定向与标记职责，iptables 降级为 fallback。  
> **原则**：可测试、模块化、稳定。

---

## 1. 背景与现状

### 1.1 当前架构（以 iptables 为核心）

```
[ App in cgroup/vproxy ]
        │ TCP connect / UDP send
        ▼
[ iptables nat OUTPUT ]  ──cgroup match──▶  VPROXY_REDIRECT chain
        │ REDIRECT/DNAT
        ▼
[ vproxy tproxy listener :10080 ]
        │ SO_ORIGINAL_DST
        ▼
[ upstream proxy ]
        ↑
[ SO_MARK 0xff ]  ← vproxy 出口连接绕过 iptables
```

**iptables 当前做的三件事：**

| 职责 | iptables 规则 | 问题 |
|------|--------------|------|
| TCP 重定向 | `nat OUTPUT … REDIRECT --to-ports` | 靠 cgroup match，不够灵活 |
| UDP 打标 | `mangle OUTPUT … MARK --set-mark 1` | 需要 tproxy 规则配合 |
| 绕过标记检测 | `-m mark --mark 0xff -j RETURN` | 用户态规则，无法在内核早期阶段拦截 |

### 1.2 eBPF Maps 方案目标

用 **`cgroup/connect4` + `cgroup/connect6`** hook（已有 `redirect.c` 实现）和 **`BPF_MAP_TYPE_LPM_TRIE` 前缀匹配 Map** 完全接管流量决策逻辑，消除对 iptables 的运行时依赖。iptables 仅在 eBPF 加载失败时作为 fallback 兜底。

---

## 2. 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                     vproxy 启动流程                          │
│                                                             │
│  1. 探测内核 eBPF 支持（>= 5.7）                             │
│  2. 尝试加载 eBPF 程序 + Maps                                │
│     ├─ 成功 → eBPF 模式（主路径）                            │
│     └─ 失败 → iptables 模式（fallback）                     │
└─────────────────────────────────────────────────────────────┘

          eBPF 模式数据流
          ───────────────

[ App in cgroup/vproxy ]
        │ connect(2) / sendto(2)
        ▼
[ eBPF cgroup/connect4 hook ]
        │  查询 bypass_map (SO_MARK == 0xff → skip)
        │  查询 cidr_bypass_map (目标 IP 在私有地址段 → skip)
        │  查询 force_proxy_map (目标 IP/CIDR → 强制代理)
        │  rewrite user_ip4/user_port → 127.0.0.1:PROXY_PORT
        │  写入 cookie_original_dst map (cookie → {orig_ip, orig_port})
        ▼
[ vproxy tproxy listener :10080 ]
        │  读取 cookie_original_dst map 获取原始目标
        │  (fallback: SO_ORIGINAL_DST getsockopt)
        ▼
[ upstream proxy ]
        ↑
[ SO_MARK 0xff，由 ebpf.GetDialerControl() 设置 ]
```

---

## 3. eBPF Maps 设计

### 3.1 Maps 一览

| Map 名称 | 类型 | Key | Value | 职责 |
|----------|------|-----|-------|------|
| `cookie_original_dst` | `HASH` | `u64` (socket cookie) | `struct original_dst` | 保存被重定向前的真实目标 |
| `cidr_bypass_map` | `LPM_TRIE` | `struct lpm_key {prefixlen, addr}` | `u8` | 不代理的目标 CIDR（私有地址段等） |
| `force_proxy_map` | `LPM_TRIE` | `struct lpm_key {prefixlen, addr}` | `u8` | 强制代理的目标 CIDR（白名单式强制） |
| `bypass_uid_map` | `HASH` | `u32` (uid) | `u8` | 某些 uid 的进程不代理 |
| `config_map` | `ARRAY` | `u32` (index) | `u64` | 运行时配置：proxy_port、bypass_mark 等 |

### 3.2 config_map 索引定义

```c
#define CFG_PROXY_PORT   0   // u64: 代理端口（host byte order）
#define CFG_BYPASS_MARK  1   // u64: SO_MARK bypass 值，默认 0xff
#define CFG_VERBOSE      2   // u64: 0=off, 1=on
```

### 3.3 cidr_bypass_map / force_proxy_map Key 结构

```c
struct lpm_key {
    __u32 prefixlen;   // 前缀长度（bits）
    __u32 addr;        // IPv4 地址（network byte order）
};
```

默认写入 `cidr_bypass_map` 的条目（在 Go 加载时初始化）：

```
127.0.0.0/8
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
169.254.0.0/16
```

---

## 4. BPF 程序设计（C）

### 4.1 文件：`proxy/ebpf/bpf/redirect.c`（重构版）

**关键逻辑流程：**

```c
SEC("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr *ctx) {
    // 1. 读取 config_map 获取 proxy_port、bypass_mark
    // 2. 检查 SO_MARK：若等于 bypass_mark → return 1（pass through）
    // 3. 检查 bypass_uid_map：若当前 uid 在 bypass 列表 → return 1
    // 4. 查询 cidr_bypass_map（LPM）：若目标 IP 命中 → return 1
    // 5. 查询 force_proxy_map（LPM）：
    //      - 若 force_proxy_map 非空且目标 IP 未命中 → return 1
    //      - （force_proxy_map 为空则代理所有）
    // 6. 保存 cookie_original_dst：
    //      cookie = bpf_get_socket_cookie(ctx)
    //      dst.ip[0] = ctx->user_ip4
    //      dst.port  = ctx->user_port
    //      bpf_map_update_elem(&cookie_original_dst, &cookie, &dst, BPF_ANY)
    // 7. 重写目标：
    //      ctx->user_ip4  = 0x7f000001  (127.0.0.1)
    //      ctx->user_port = bpf_htons(proxy_port)
    // 8. return 1
}
```

**与现有实现的差异：**

| 现有 `redirect.c` | 重构后 |
|-------------------|--------|
| `volatile const` 写死 proxy_port | 从 `config_map` 动态读取，支持热更新 |
| 私有地址硬编码在 C | 通过 `cidr_bypass_map`（LPM_TRIE）动态配置 |
| 无 force_proxy 概念 | 新增 `force_proxy_map`，支持精细控制 |
| 无 UID 过滤 | 新增 `bypass_uid_map` |

### 4.2 文件：`proxy/ebpf/bpf/tc_redirect.c`（保留）

TC ingress 程序用于**路由器/网关场景**（TC 层对其他主机流量打标），与本方案正交，保持不变。

---

## 5. Go 侧模块设计

### 5.1 包结构

```
proxy/ebpf/
├── bpf/
│   ├── redirect.c          ← BPF 程序（重构）
│   └── tc_redirect.c       ← TC 程序（保留不变）
├── bpf_bpfel.go            ← bpf2go 生成（重新生成）
├── bpf_bpfel.o             ← 编译产物
├── ebpf_linux.go           ← SO_MARK dialer control（保留）
├── ebpf_stub.go            ← 非 Linux stub（保留）
├── maps.go                 ← [NEW] Maps 操作的统一接口
├── loader.go               ← [NEW] eBPF 程序加载与生命周期
├── loader_test.go          ← [NEW] 单元/集成测试
└── maps_test.go            ← [NEW] Map CRUD 测试
```

### 5.2 `loader.go` — 加载器接口

```go
// LoadResult 表示一次加载的结果，包含所有 Maps 的句柄。
type LoadResult struct {
    CookieOriginalDst *ebpf.Map
    CidrBypassMap     *ebpf.Map
    ForceProxyMap     *ebpf.Map
    BypassUIDMap      *ebpf.Map
    ConfigMap         *ebpf.Map
    cgroupFd          int
    objs              bpfObjects
}

// Load 加载 BPF 对象，挂载到指定 cgroup，写入初始配置。
// 失败时返回 (nil, err)，由调用方决定是否 fallback。
func Load(cgroupPath string, proxyPort uint16, bypassMark uint32) (*LoadResult, error)

// Unload 卸载 BPF 程序，关闭所有 Map FD。
func (r *LoadResult) Unload() error

// IsKernelSupported 检查内核版本是否 >= 5.7（支持 cgroup sockaddr hook）。
func IsKernelSupported() bool
```

### 5.3 `maps.go` — Maps 操作接口

```go
// CIDRBypassManager 管理 cidr_bypass_map。
type CIDRBypassManager struct{ m *ebpf.Map }

func (c *CIDRBypassManager) Add(cidr string) error
func (c *CIDRBypassManager) Remove(cidr string) error
func (c *CIDRBypassManager) List() ([]string, error)

// ForceProxyManager 管理 force_proxy_map。
type ForceProxyManager struct{ m *ebpf.Map }

func (f *ForceProxyManager) Add(cidr string) error
func (f *ForceProxyManager) Remove(cidr string) error

// LookupOriginalDst 从 cookie_original_dst 查询原始目标。
// 这是 tproxy 层 SO_ORIGINAL_DST 的 eBPF 替代方案。
func LookupOriginalDst(m *ebpf.Map, cookie uint64) (*OriginalDst, error)

// DeleteOriginalDst 在连接建立后删除 Map 条目，防止泄漏。
func DeleteOriginalDst(m *ebpf.Map, cookie uint64) error
```

### 5.4 `Manager` — 顶层编排（统一 eBPF/iptables 决策）

新增 `proxy/redirect` 包，提供统一接口：

```go
// proxy/redirect/manager.go

type Mode int

const (
    ModeAuto     Mode = iota // 自动探测，优先 eBPF
    ModeEBPF                 // 强制 eBPF
    ModeIPTables             // 强制 iptables
)

type Manager struct {
    mode   Mode
    result *ebpfpkg.LoadResult  // eBPF 模式时有值
}

// Setup 根据 mode 选择实现，自动处理 fallback。
func Setup(cgroupPath string, proxyPort uint16, bypassMark uint32, mode Mode) (*Manager, error) {
    if mode == ModeIPTables {
        return setupIPTables(proxyPort)
    }

    // 尝试 eBPF
    if ebpfpkg.IsKernelSupported() {
        r, err := ebpfpkg.Load(cgroupPath, proxyPort, bypassMark)
        if err == nil {
            return &Manager{mode: ModeEBPF, result: r}, nil
        }
        log.Printf("[redirect] eBPF load failed: %v, falling back to iptables", err)
    }

    if mode == ModeEBPF {
        return nil, fmt.Errorf("eBPF required but unavailable")
    }

    return setupIPTables(proxyPort)
}

// Teardown 清理所有规则/程序。
func (m *Manager) Teardown() error

// LookupOriginalDst 获取原始目标地址（eBPF map 或 SO_ORIGINAL_DST）。
func (m *Manager) LookupOriginalDst(conn net.Conn) (*net.TCPAddr, error)
```

---

## 6. tproxy 层集成

`proxy/tproxy/tproxy_linux.go` 需要在 eBPF 模式下优先查询 `cookie_original_dst` Map：

```go
func GetOriginalDst(conn *net.TCPConn, ebpfMap *ebpf.Map) (*net.TCPAddr, error) {
    // 1. 若 ebpfMap != nil，获取 socket cookie，查询 Map
    if ebpfMap != nil {
        cookie, err := getSockCookie(conn)
        if err == nil {
            dst, err := ebpfmaps.LookupOriginalDst(ebpfMap, cookie)
            if err == nil {
                ebpfmaps.DeleteOriginalDst(ebpfMap, cookie)  // GC
                return dst.ToTCPAddr(), nil
            }
        }
    }
    // 2. Fallback: SO_ORIGINAL_DST getsockopt（兼容 iptables 模式）
    return getOriginalDstViaGetsockopt(conn)
}
```

**获取 socket cookie 的方法：**

```go
func getSockCookie(conn *net.TCPConn) (uint64, error) {
    raw, err := conn.SyscallConn()
    if err != nil { return 0, err }
    var cookie uint64
    raw.Control(func(fd uintptr) {
        val, _ := syscall.GetsockoptUint64(int(fd), syscall.SOL_SOCKET, unix.SO_COOKIE)
        cookie = val
    })
    return cookie, nil
}
```

---

## 7. 协议支持矩阵

基于对现有代码（`redirect.c`、`iptables_linux.go`、`tproxy_linux.go`、`tproxy_udp_linux.go`）的实际分析：

| 协议 | eBPF 主路径 | iptables fallback | 原始目标获取 | 备注 |
|------|------------|-------------------|------------|------|
| **IPv4 TCP** | ✅ `cgroup/connect4` hook | ✅ `nat OUTPUT REDIRECT` | ✅ `SO_ORIGINAL_DST` | 完整支持 |
| **IPv4 UDP** | ✅ `cgroup/connect4` hook | ✅ `mangle + TPROXY` | ✅ `IP_RECVORIGDSTADDR` | 完整支持 |
| **IPv6 TCP** | ✅ `cgroup/connect6` hook | ❌ 无 `ip6tables` 规则 | ✅ `IP6T_SO_ORIGINAL_DST` | **fallback 下不可用** |
| **IPv6 UDP** | ⚠️ hook 存在但路径不完整 | ❌ 无规则 | ⚠️ 代码存在但 listener 绑定 `0.0.0.0` | **当前不可用** |

### 7.1 各缺口的根因

#### IPv6 TCP — iptables fallback 缺失
`iptables_linux.go` 完全没有 `ip6tables` 规则。当 eBPF 不可用时，IPv6 TCP 流量不会被拦截。

**修复方案**（Phase 4）：在 `SetupRules` 中镜像添加 `ip6tables` 规则：
```bash
ip6tables -t nat -N VPROXY_REDIRECT6 ...
ip6tables -t nat -A OUTPUT -p tcp -m cgroup --path "vproxy" -j VPROXY_REDIRECT6
```

#### IPv6 UDP — 两个层面都缺失

1. **BPF 层**：`cgroup/connect6` 重定向到 `::1`，但 tproxy listener 绑定 `0.0.0.0` 而非 `[::]`，收不到 IPv6 包
2. **iptables 层**：`tproxy_udp_linux.go` 的 `ListenUDPTransparent` 需改为 `[::]:PORT` 并启用 `IPV6_V6ONLY=0`

**修复方案**（Phase 4）：
```go
// tproxy_udp_linux.go
conn, err := lc.ListenPacket(context.Background(), "udp6", fmt.Sprintf("[::]:%" d", port))
// 同时设置 IPV6_V6ONLY = 0 以接受 IPv4-mapped IPv6 地址
```

### 7.2 当前实际可用范围

> [!IMPORTANT]
> **eBPF 模式（内核 ≥ 5.7）**：IPv4 TCP + IPv4 UDP 完整工作；IPv6 TCP 工作（BPF hook 有效）；IPv6 UDP 不可用。
>
> **iptables fallback 模式**：仅 IPv4 TCP + IPv4 UDP 可用；IPv6 完全不工作。

---

## 9. 内核版本与 fallback 策略

### 7.1 兼容性矩阵

| 内核版本 | cgroup/connect4 hook | LPM_TRIE Map | SO_COOKIE | 结果 |
|----------|---------------------|--------------|-----------|------|
| < 4.10   | ✗ | ✗ | ✗ | iptables only |
| 4.10–5.6 | ✓ (attach 受限) | ✓ | ✓ | iptables fallback |
| ≥ 5.7    | ✓ (BPF_CGROUP_INET4_CONNECT) | ✓ | ✓ | **eBPF 主路径** |
| ≥ 5.13   | ✓ + sleepable | ✓ | ✓ | eBPF 主路径（更佳） |

### 7.2 Fallback 触发条件

```
IsKernelSupported() == false
  OR bpf2go Load 返回 EPERM
  OR bpf2go Load 返回 ENOSYS
  OR cgroup attach 返回错误
  → 自动切换到 iptables.SetupRules()
```

### 7.3 配置字段扩展

在 `internal/config.go` 的 `Config` 中添加：

```go
type Config struct {
    // 已有字段...
    EnableEbpf    *bool  `json:"enable_ebpf,omitempty"`
    EbpfMode      string `json:"ebpf_mode,omitempty"`  // "auto"|"ebpf"|"iptables"，默认 "auto"
}
```

---

## 10. 测试方案

### 8.1 单元测试（无需 root，无需真实内核）

**文件：`proxy/ebpf/maps_test.go`**

```go
// 使用 cilium/ebpf 的 testutil 或 mock Map
func TestCIDRBypassManager_AddRemove(t *testing.T) {
    // 构造内存 Map（BPF_MAP_TYPE_LPM_TRIE）
    // 测试 Add("10.0.0.0/8") → lookup 10.1.2.3 命中
    // 测试 Remove("10.0.0.0/8") → lookup 10.1.2.3 未命中
}

func TestLookupOriginalDst_NotFound(t *testing.T) {
    // 空 map，查询任意 cookie 应返回 ErrKeyNotExist
}

func TestIPKeyEncoding(t *testing.T) {
    // 验证 192.168.1.1 的 LPM key 编码在大小端机器上的正确性
    // 重点测试字节序转换逻辑（参考 tc_linux.go 的遗留问题）
}
```

### 8.2 集成测试（需要 Linux + CAP_NET_ADMIN）

**文件：`proxy/ebpf/loader_test.go`**

```go
//go:build linux && integration

func TestLoad_RealKernel(t *testing.T) {
    if !ebpf.IsKernelSupported() {
        t.Skip("kernel < 5.7")
    }
    // 需要 root 或 CAP_BPF + CAP_NET_ADMIN
    r, err := ebpf.Load("/sys/fs/cgroup/vproxy", 10080, 0xff)
    require.NoError(t, err)
    defer r.Unload()

    // 验证 Maps 可以正常读写
    mgr := ebpf.NewCIDRBypassManager(r.CidrBypassMap)
    assert.NoError(t, mgr.Add("192.168.0.0/16"))
    list, _ := mgr.List()
    assert.Contains(t, list, "192.168.0.0/16")
}
```

### 8.3 redirect.Manager 的 Fallback 测试

```go
//go:build linux

func TestManager_FallbackToIPTables(t *testing.T) {
    // 强制 eBPF 失败（传入非法 cgroupPath）
    m, err := redirect.Setup("/nonexistent/cgroup", 10080, 0xff, redirect.ModeAuto)
    // 应该成功（fallback 到 iptables）
    require.NoError(t, err)
    assert.Equal(t, redirect.ModeIPTables, m.ActiveMode())
    m.Teardown()
}
```

### 8.4 端到端测试（CI 环境）

```bash
# scripts/test_e2e.sh
# 需要 Linux 内核 >= 5.7，在 CI 中用 privileged 容器运行
set -e

# 启动 vproxy（eBPF 模式）
sudo ./bin/vproxy run --ebpf-mode=ebpf &
VP_PID=$!

# 用 curl 发起连接，验证流量被正确重定向
curl -s --max-time 5 http://httpbin.org/ip | grep origin

# 检查 eBPF Map 中是否有 cookie 条目（连接过程中）
# bpftool map dump name cookie_original_dst

kill $VP_PID
```

### 8.5 测试执行命令

```bash
# 纯单元测试（无需特权）
go test ./proxy/ebpf/... -v -run 'Unit|Encoding|NotFound'

# 集成测试（需要 root）
sudo go test ./proxy/ebpf/... -v -tags integration -run 'Real'

# redirect.Manager fallback 测试
sudo go test ./proxy/redirect/... -v

# 全量测试（包括 e2e）
make test-all
```

---

## 11. 实现路线图

### Phase 1：eBPF Maps 基础设施（优先）

- [ ] 重构 `bpf/redirect.c`：用 `config_map` + `cidr_bypass_map`（LPM_TRIE）替换硬编码常量
- [ ] 重新运行 `go generate ./proxy/ebpf/...`，更新 `bpf_bpfel.go`
- [ ] 实现 `proxy/ebpf/maps.go`（CIDRBypassManager、ForceProxyManager、LookupOriginalDst）
- [ ] 实现 `proxy/ebpf/loader.go`（IsKernelSupported、Load、Unload）
- [ ] 编写 `maps_test.go` 单元测试

### Phase 2：redirect.Manager 统一层

- [ ] 新建 `proxy/redirect/` 包
- [ ] 实现 `Manager.Setup` 的 auto/ebpf/iptables 三模式
- [ ] `internal/app.go` 改用 `redirect.Manager`，去除直接的 `iptables.SetupRules` 调用
- [ ] 编写 fallback 集成测试

### Phase 3：tproxy 层集成

- [ ] `proxy/tproxy/tproxy_linux.go` 支持从 `cookie_original_dst` Map 查询原始目标
- [ ] Map cookie GC：连接关闭后删除条目（防止 Map 满）
- [ ] 编写 `getSockCookie` 的跨平台 stub

### Phase 4：稳定性与运维

- [ ] Map 大小监控：`cookie_original_dst` 满时记录告警（max_entries 可调）
- [ ] 添加 `config_map` 热更新支持（不需要重新 load BPF 程序）
- [ ] 添加 CLI 命令：`vproxy ebpf status`（显示当前模式、Map 条目数）
- [ ] 更新 `docs/design.md` 反映新架构

---

## 12. 稳定性设计要点

### 10.1 Map 内存泄漏防护

`cookie_original_dst` 是 per-connection 的临时存储。若连接异常关闭，tproxy 层可能读不到 cookie，条目会残留。

**缓解措施：**
1. `max_entries = 65536`（足够大，连接数高时不会立即满）
2. tproxy 读取成功后**立即删除**条目（`DeleteOriginalDst`）
3. 定时 GC goroutine（可选）：每 60s 扫描 Map，删除超过 30s 的条目（需 value 中加 timestamp 字段）

### 10.2 BPF Verifier 兼容性

- 所有循环使用 `#pragma unroll` 或有界迭代
- LPM_TRIE lookup 返回值必须做 NULL 检查（Verifier 强制要求）
- `bpf_map_update_elem` 失败不应阻塞数据包（`connect` hook 返回 1 即 pass）

### 10.3 Cgroup 挂载点稳定性

eBPF cgroup 程序挂载到 `/sys/fs/cgroup/vproxy`。若 cgroup 目录被删除（如容器重启），程序自动失效。

**处理：**
- `loader.go` 持有 cgroupFd（通过 `open(path, O_RDONLY)` 获取），即使路径消失，FD 仍有效
- 进程退出时 `Unload()` 关闭 FD，内核自动分离 BPF 程序

### 10.4 并发安全

- `LoadResult` 中的 Map FD 是只读引用，多 goroutine 并发读写 Map 是安全的（内核保证原子性）
- `CIDRBypassManager` 等管理器无需加锁（Map 操作本身原子）
- `config_map` 的更新使用 `BPF_ANY`，确保写入原子可见

---

## 13. 与现有代码的关键差异

| 维度 | 现有（iptables 主导） | 新方案（eBPF Maps 主导） |
|------|----------------------|------------------------|
| 原始目标获取 | `SO_ORIGINAL_DST` getsockopt | `cookie_original_dst` Map（优先），getsockopt（fallback） |
| 绕过规则 | iptables `-m mark --mark 0xff -j RETURN` | eBPF hook 内检查 socket mark，直接 return 1 |
| 私有地址过滤 | iptables `-d 192.168.0.0/16 -j RETURN` 等 | `cidr_bypass_map` LPM_TRIE，运行时可动态修改 |
| 配置更新 | 重新执行 shell 命令 | 写入 `config_map`，BPF 程序下次执行时读取 |
| 可观测性 | `iptables -L -n` | `bpftool map dump`，或 vproxy CLI |
| 权限需求 | `CAP_NET_ADMIN` + `sudo` | `CAP_BPF` + `CAP_NET_ADMIN`（同现有） |
| 内核依赖 | 任意支持 iptables 的内核 | Linux >= 5.7（低版本自动 fallback） |
