# Module Spec: Linux 平台基于 eBPF 与 Proc 探针的 ProcessInspector 实现规范

## 1. Overview
本模块定义 Linux 操作系统环境下 `ProcessInspector` 进程归属探测引擎的完整实现规范（SPEC-LINUX-PROC-001 ~ SPEC-LINUX-PROC-005）。

### 痛点与目标
1. **现有空桩与功能割裂**：目前在 Linux 下，`proxy/driver/driver_linux.go` 及 `proxy/tproxy/tproxy_linux.go` 的 `GetProcessNameByConn` 和 `GetProcessNameByPort` 均返回 `ErrProcessInspectionUnsupported`，导致所有形如 `PROCESS,curl,DIRECT` 或 `PROCESS,code-server,PROXY` 的进程分流规则在 Linux 上彻底失效。
2. **eBPF 纳管时机绝佳**：在 cgroup eBPF 重定向模式下，`sock4_connect` / `sock6_connect` 运行于发起连接进程的上下文（Process Context）中，内核辅助函数 `bpf_get_current_pid_tgid()` 与 `bpf_get_current_comm()` 可零额外开销获取真实的调用端 PID 与进程名。
3. **TUN / 非 eBPF 模式需要兜底**：在纯 TUN 模式或未挂载 eBPF 的场景下，需要提供基于 `/proc/net/tcp` + `/proc/<pid>/fd` 的 inode 反查兜底机制，并辅以 LRU/TTL 缓存保证高吞吐与低时延。

---

## 2. Architecture & Design

### 2.1 双引擎探测分层架构 (Dual-Engine Architecture)

```
       GetProcessNameByConn(conn) / GetProcessNameByPort(port)
                               │
                               ▼
            ┌──────────────────────────────────────┐
            │  Tier 1: eBPF Map / In-Memory Cache  │ ── (Hit: < 1µs, O(1)) ──► 返回 (comm, pid)
            └──────────────────────────────────────┘
                               │ (Miss / Non-eBPF)
                               ▼
            ┌──────────────────────────────────────┐
            │   Tier 2: /proc Socket Inode 反查    │ ── (Hit: ~1-2ms) ───────► 写入短缓存并返回
            └──────────────────────────────────────┘
                               │ (Miss)
                               ▼
                     返回 ("", 0, ErrNotFound)
```

### 2.2 Tier 1: eBPF 内核元数据捕获规范

#### 1. 数据结构对齐（`proxy/ebpf/bpf/redirect.c` 与 Go `OriginalDst`）
扩展 `struct original_dst`：
```c
struct original_dst {
    __u32 ip[4];    /* 目的 IP (网络字节序) */
    __u32 port;     /* 目的端口 (网络字节序) */
    __u32 family;   /* AF_INET 或 AF_INET6 */
    __u32 pid;      /* 发起进程 PID */
    char  comm[16]; /* 发起进程名称 (task_struct comm) */
};
```

#### 2. eBPF Hook 填充
- **`cgroup/connect4` & `cgroup/connect6`**：
  ```c
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  dst.pid = (__u32)(pid_tgid >> 32);
  bpf_get_current_comm(dst.comm, sizeof(dst.comm));
  ```
  在写入 `tcp_cookie_map` 与 `udp_orig_dst` 时完整保留 `pid` 与 `comm`。
- **`sockops` (TCP Active Established)**：
  从 `tcp_cookie_map` 取出 `dst` 时，连同 `pid` 和 `comm` 一并写入 `tcp_orig_dst`。
- **`cgroup/sendmsg4` & `cgroup/sendmsg6`**：
  同样填充 UDP 未连接 socket 的 `pid` 与 `comm`。

#### 3. Go 用户态数据读取与关联
- 当 `LookupTCPOrigDst` 解析原始目标时，将 `client_port -> {pid, comm}` 缓存在连接进程缓存池中（TTL: 10 秒）。
- `linuxProcessInspector.GetProcessNameByConn(conn)` 和 `GetProcessNameByPort(port)` 优先命中该缓存。

---

### 2.3 Tier 2: `/proc` 文件系统 Inode 反查引擎（TUN / 备用引擎）

1. **查找 socket inode**：
   - 读取 `/proc/net/tcp`、`/proc/net/tcp6`、`/proc/net/udp`、`/proc/net/udp6`；
   - 根据源端口（Hex 格式）匹配连接条目，提取 `inode` 字段。
2. **反查所有者进程**：
   - 遍历 `/proc/[0-9]*/fd`（或维护 inode 缓存池），匹配指向 `socket:[<inode>]` 的文件描述符；
   - 命中时读取 `/proc/<pid>/comm` 获取进程短名，必要时读取 `/proc/<pid>/cmdline` 获取完整可执行文件名。
3. **缓存优化**：
   - 引入带有并发安全的读写锁的 LRU / TTL 缓存表（默认容量 1024，TTL 5 秒）；
   - 对已解析过的端口/inode 在有效期内直接返回，杜绝高频访问下的 `/proc` 扫描开销。

---

## 3. Acceptance Criteria (BDD)

### Feature: eBPF 内核进程元数据捕获

#### Scenario 1: [SPEC-LINUX-PROC-001] eBPF 模式下建立 TCP 连接时捕获正确的 PID 与进程名
- **Given** vproxy 启用 eBPF 重定向模式
- **When** 某进程（例如 `curl`，PID 12345）发起外联 TCP 连接
- **Then** `cgroup/connect4` 正确捕获 PID `12345` 与 Comm `"curl"`
- **And** 用户态读取 `tcp_orig_dst` 能成功反解出 `PID: 12345` 与 `Process: "curl"`

#### Scenario 2: [SPEC-LINUX-PROC-002] eBPF 模式下发送 UDP 报文时捕获正确的进程元数据
- **Given** vproxy 启用 eBPF 重定向模式
- **When** 某进程发送外联 UDP 数据包
- **Then** `udp_orig_dst` 中携带发起进程的 PID 与 Comm 字符串
- **And** 用户态通过源端口查询能成功获取进程元数据

---

### Feature: `/proc` Inode 反查与回退引擎

#### Scenario 3: [SPEC-LINUX-PROC-003] 在未运行 eBPF 或 TUN 模式下通过 /proc 反查进程
- **Given** 未挂载 eBPF 或处于 TUN 模式
- **When** 应用程序通过本地端口发起网络通信并被拦截
- **Then** `linuxProcessInspector.GetProcessNameByPort(port)` 通过 `/proc/net/tcp` 与 `/proc/<pid>/fd` 成功反查出进程名与 PID
- **And** 查询耗时受控在轻量级范围（< 10ms）

#### Scenario 4: [SPEC-LINUX-PROC-004] 进程元数据缓存有效抑制重复文件系统遍历
- **Given** 某持久连接频繁发生数据交互或短连接复用同一端口
- **When** 5 秒内连续多次调用 `GetProcessNameByPort`
- **Then** 第 2 次及以后的查询直接命中内存缓存，不触发 `/proc` 重复扫描

---

### Feature: 规则引擎端到端生效

#### Scenario 5: [SPEC-LINUX-PROC-005] Linux 平台 PROCESS 规则端到端生效
- **Given** 规则配置包含 `PROCESS,curl,PROXY` 与 `PROCESS,mytool,DIRECT`
- **When** `curl` 发起网络请求被 vproxy 拦截
- **Then** `ProxyHandler.forward` 识别到 `Process: "curl"`
- **And** 规则引擎精确命中 `PROCESS,curl,PROXY` 路由分支
