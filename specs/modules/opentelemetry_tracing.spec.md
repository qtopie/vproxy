# Module Spec: OpenTelemetry 分布式链路追踪 (Tracing) 规范

## 1. Overview
本规范定义 `vproxy` 在 Linux 环境下集成 OpenTelemetry (OTel) 分布式追踪上报的架构规范（SPEC-OTEL-001 ~ SPEC-OTEL-006）。
结合方案 A 架构：**用户态 OTel Go SDK (Tracer & OTLP Exporter) + eBPF/Proc 捕获的进程元数据深度关联**。

### 1.1 痛点与目标
1. **全链路透明感知**：作为透明代理和反向代理，网络流量经过拦截、DNS 解析/Fake-IP 反解、规则分流、上游重试、L7 重写与流式拷贝。传统文本日志在排查偶发超时或链路瓶颈时效率低，缺乏标准的分布式追踪支持。
2. **eBPF 进程上下文自动关联**：利用 Linux eBPF/Proc 提供的发起进程（`PID`、`Comm`、`Executable`），在链路中自动关联发出请求的本地客户端进程信息，做到真正的系统无侵入可观测性。
3. **标准 OTLP 协议输出**：支持向标准 OpenTelemetry Collector、Jaeger、Tempo 等主流 APM 系统导出 Traces，支持 gRPC / HTTP 传输及可配置的采样率。
4. **零开销旁路设计**：未启用 OTel 时必须零性能开销；启用时通过异步批处理 Exporter 保证高吞吐网络转发路径不被阻塞。

---

## 2. Architecture & Design

### 2.1 整体架构

```
 [Client Process (e.g. curl, agy)]
          │  TCP / UDP / HTTP
          ▼
 ┌────────────────────────────────────────────────────────┐
 │ vproxy (Linux)                                         │
 │                                                        │
 │ 1. Inbound Intercept (TUN / TPROXY / eBPF / Local Port) │
 │    ├─ Extract Process via Driver (eBPF Map / /proc)    │ ──► [Span: vproxy.session]
 │    │  (Attributes: process.pid, process.name, client.*) │
 │    │                                                   │
 │ 2. Route & DNS Resolution                              │
 │    ├─ Fake-IP / SNI / L4 Rules Engine                  │ ──► [Child Span: vproxy.route]
 │    │  (Attributes: rule.type, rule.target, net.peer.*)  │
 │    │                                                   │
 │ 3. Upstream Connect / Retry Loop                       │
 │    ├─ Direct Dial or Upstream Proxy Tunnel             │ ──► [Child Span: vproxy.upstream_dial]
 │    │  (Attributes: upstream.addr, dial.attempt)        │
 │    │                                                   │
 │ 4. Data Relay / L7 Rewrite                             │
 │    ├─ Rewrite (if applicable) & Bi-directional Stream  │ ──► [Child Span: vproxy.relay]
 │    │  (Attributes: bytes.sent, bytes.rcvd, duration)   │
 └─────────────────────────┬──────────────────────────────┘
                           │ Batch Span Exporter (Async OTLP gRPC/HTTP)
                           ▼
              ┌────────────────────────┐
              │ OTel Collector / Tempo │
              └────────────────────────┘
```

### 2.2 配置定义 (`internal/config.go`)

在 `Config` 中新增 `otel` 结构体：
```json
{
  "otel": {
    "enabled": true,
    "endpoint": "localhost:4317",
    "protocol": "grpc",
    "insecure": true,
    "service_name": "vproxy",
    "sample_rate": 1.0
  }
}
```

```go
type OtelConfig struct {
    Enabled     bool    `json:"enabled"`
    Endpoint    string  `json:"endpoint,omitempty"`     // 默认 "localhost:4317"
    Protocol    string  `json:"protocol,omitempty"`     // "grpc" (默认) 或 "http"
    Insecure    bool    `json:"insecure,omitempty"`     // 默认 true
    ServiceName string  `json:"service_name,omitempty"` // 默认 "vproxy"
    SampleRate  float64 `json:"sample_rate,omitempty"`  // 0.0 ~ 1.0, 默认 1.0
}
```

### 2.3 Span 拓扑与语义属性 (Semantic Conventions)

#### 1. 根 Span：`vproxy.session`
- **SpanKind**: `SpanKindServer`
- **Attributes**:
  - `net.transport`: `"tcp"` / `"udp"`
  - `client.address`: 客户端 IP (string)
  - `client.port`: 客户端 Port (int)
  - `destination.address`: 原始目标 IP/域名 (string)
  - `destination.port`: 原始目标 Port (int)
  - `vproxy.driver`: `"ebpf"` / `"tproxy"` / `"tun"` / `"local"`
  - `process.pid`: 调用方 PID (int，Linux eBPF / /proc 识别结果)
  - `process.executable.name`: 调用方进程名 (string，例如 `"curl"`, `"code-server"`)

#### 2. 子 Span：`vproxy.route`
- **SpanKind**: `SpanKindInternal`
- **Attributes**:
  - `rule.type`: `"DOMAIN"` / `"DOMAIN-SUFFIX"` / `"PROCESS"` / `"IP-CIDR"` / `"FINAL"` 等
  - `rule.action`: `"PROXY"` / `"DIRECT"` / `"REJECT"`
  - `dns.resolved_host`: Fake-IP 恢复后的域名 / SNI 嗅探域名 (string)

#### 3. 子 Span：`vproxy.upstream_dial`
- **SpanKind**: `SpanKindClient`
- **Attributes**:
  - `upstream.address`: 最终外联的 Upstream 地址（若为 DIRECT 则为 target，若为 SOCKS5 则为代理节点地址）
  - `dial.attempt`: 重试次数 (int)
  - `dial.timeout_ms`: 超时配置 (int)
- **Events / Status**: 记录各重试节点的连接错误状态，成功则为 `StatusOk`。

#### 4. 子 Span：`vproxy.relay`
- **SpanKind**: `SpanKindInternal`
- **Attributes**:
  - `traffic.bytes_sent`: 客户端发送到服务端的字节数 (int64)
  - `traffic.bytes_received`: 服务端响应到客户端的字节数 (int64)
  - `duration_ms`: 转发持续时长 (int64)

### 2.4 并发安全与状态发布契约 (Concurrency Contract)

OTel 全局 Tracer 状态被两类执行流并发访问：

| 访问方 | 执行流 | 频率 |
|---|---|---|
| `GetOtelTracer()` / `IsOtelActive()` | 每连接热路径（`internal/handler.go` 的 `forward()`） | 每连接多次，高并发 |
| `InitOtelTracer()` / `shutdown()` | 启动、`watchConfig` 配置热重载、Web `/config` 保存 | 极低频 |

**不变量 (Invariants)：**

- **INV-OTEL-C1（无锁读，消除数据竞争）**：热路径读取必须是无锁的原子读取。Tracer 与 active 标志必须作为**同一个不可变快照 (snapshot)** 发布，禁止出现「`active=true` 但 tracer 仍为 noop」或「tracer 已换新但 `active=false`」的撕裂 (torn) 组合。
- **INV-OTEL-C2（发布顺序）**：新的 `TracerProvider` 必须**完整构建成功之后**才允许原子发布；构建过程中任何一步失败都必须返回 error 且**保留旧状态不变**，不得把系统降级为 noop。
- **INV-OTEL-C3（Shutdown 不得阻塞热路径）**：禁止在持有热路径会等待的锁的情况下调用 `TracerProvider.Shutdown()`。正确顺序为：① 原子发布新快照 → ② 释放写锁 → ③ 在锁外关闭旧 Provider。
- **INV-OTEL-C4（竞争检测）**：`go test -race ./internal/...` 在「init/shutdown 与并发 `GetOtelTracer()`/`IsOtelActive()` 交织」的压力用例下必须**零告警**。

**实现方式（唯一读写入口）**：以 `atomic.Pointer[otelState]` 承载不可变快照（`otelState{ tracer trace.Tracer; active bool }`），读侧 `Load()`、写侧 `Store()`；`InitOtelTracer` 与 `shutdown` 共用一个互斥锁**仅串行化写入者**，绝不串行化热路径读取。

---

## 3. Acceptance Criteria (BDD)

### Feature: OpenTelemetry Tracing

#### Scenario 1: [SPEC-OTEL-001] OTel 配置解析与生命周期管理
- **Given** 配置文件中配置了 `otel: { enabled: true, endpoint: "127.0.0.1:4317", protocol: "grpc" }`
- **When** vproxy 初始化启动
- **Then** OTel TracerProvider 被成功初始化，后台建立 OTLP 批处理上报通道
- **And** 当 vproxy 关闭或接收退出信号时，TracerProvider 优雅 Flush 并关闭

#### Scenario 2: [SPEC-OTEL-002] 禁用 OTel 时的零开销
- **Given** 配置文件中未启用 OTel (`otel.enabled = false` 或省略)
- **When** 处理网络连接时
- **Then** 全局 Tracer 为 NoopTracer，不触发任何额外的对象分配或网络上报

#### Scenario 3: [SPEC-OTEL-003] 会话端到端 Span 产生与父子关系
- **Given** OTel 已启用
- **When** 一个 TCP 连接被拦截并成功转发给目标或上游
- **Then** 生成根 Span `vproxy.session`，包含子 Span `vproxy.route`、`vproxy.upstream_dial`、`vproxy.relay`
- **And** 客户端/服务端流量字节计数正确记录在 `vproxy.relay` 的属性中

#### Scenario 4: [SPEC-OTEL-004] Linux eBPF/Proc 进程元数据自动注入 Span
- **Given** 在 Linux 环境下运行并开启 eBPF 或启用 /proc 探针
- **When** 某进程（例如 PID 为 8888 的 `curl`）发起请求
- **Then** `vproxy.session` 的 Attributes 中必须包含 `process.pid = 8888` 和 `process.executable.name = "curl"`

#### Scenario 5: [SPEC-OTEL-005] 上游连接失败重试记录
- **Given** 配置了多个 Upstream 代理节点且首个节点不可达
- **When** vproxy 发生重试
- **Then** `vproxy.upstream_dial` 记录每次重试失败的事件 (Event) 或错误状态，并在最终成功节点建立时正确返回

#### Scenario 6: [SPEC-OTEL-006] Harness 单元与集成测试验证
- **Given** 使用 in-memory SpanRecorder 或本地 Mock OTLP 收集端
- **When** 执行自动化 Harness 测试
- **Then** 捕获并断言所有的 Span 结构、父子级联与核心 Attributes 符合预期

#### Scenario 7: [SPEC-OTEL-007] 全局 Tracer 状态并发安全
- **Given** 多个 goroutine 正在并发读取 `GetOtelTracer()` 与 `IsOtelActive()`（模拟每连接 `forward()` 的访问模式）
- **When** 同时反复执行 `InitOtelTracer()`（启用/禁用交替）与 `shutdown()`
- **Then** 在 `go test -race` 下**零 data race 告警**（INV-OTEL-C4）
- **And** 任一时刻读到的 `(tracer, active)` 组合始终自洽：`active == true` 蕴含 tracer 非 noop（INV-OTEL-C1）
- **And** `Shutdown` 执行期间热路径读取不阻塞（INV-OTEL-C3）
- **And** 当 `InitOtelTracer()` 因 exporter 创建失败而返回 error 时，旧状态保持不变（INV-OTEL-C2）
