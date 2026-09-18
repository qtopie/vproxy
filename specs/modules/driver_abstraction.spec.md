# Module Spec: 跨平台驱动与进程探测统一抽象引擎 (Driver Abstraction)

## 1. Overview
本模块定义 `vproxy` 传输层与系统级底层驱动的跨平台统一抽象层（`Driver Abstraction`，SPEC-DRIVER-001 ~ SPEC-DRIVER-005）。

### 痛点与目标
当前各操作系统（Linux / Windows / macOS）实现存在割裂：
1. **核心层平台分叉严重**：`internal/handler.go` 和 `internal/app.go` 充斥着大量 `if runtime.GOOS == "..."` 硬编码判断；
2. **驱动启动与清理入口不一**：`StartWindowsTransparent`、`StartLinuxTransparent`、`StartDarwinTransparent` 参数与行为不一致；
3. **功能支持不对称且静默**：`PROCESS` 规则在 Linux 上静默忽略，无统一错误契约；
4. **DNS 劫持逻辑重复散落**：各平台在 UDP 循环内各自手写 Fake-IP 拦截应答。

本模块通过建立 **统一驱动接口契约 + Go Build Tags 静态注入**，彻底解耦核心业务层与操作系统底层差异。

---

## 2. Interface / API Contract

### 2.1 驱动接口 `InterceptDriver`
```go
package driver

// ConnectionCallback 定义底层拦截到连接时的回调签名
type ConnectionCallback func(conn net.Conn, target string)

// InterceptDriver 定义各操作系统透明代理驱动标准契约
type InterceptDriver interface {
    // Name 返回驱动标识 (如 "linux-ebpf", "linux-tun", "windows-wintun", "darwin-pf")
    Name() string
    // Start 启动透明拦截并将捕获到的 TCP/UDP 流量传递给回调
    Start(ctx context.Context, onTCP ConnectionCallback, onUDP ConnectionCallback) error
    // Cleanup 释放网卡、路由、防火墙规则与套接字
    Cleanup() error
}
```

### 2.2 进程归属探测器 `ProcessInspector`
```go
var ErrProcessInspectionUnsupported = errors.New("process inspection is not supported on this platform")

// ProcessInspector 定义各平台连接归属进程的探测契约
type ProcessInspector interface {
    // GetProcessNameByConn 根据连接探测进程名称与 PID
    GetProcessNameByConn(conn net.Conn) (name string, pid int, err error)
    // GetProcessNameByPort 根据本地源端口探测进程名称与 PID
    GetProcessNameByPort(port int) (name string, pid int, err error)
}
```

### 2.3 环路与 WSL 转发探测器 `RelayDetector`
```go
// RelayDetector 识别是否为来自虚拟子系统（如 WSL2）或需要特殊放行的外来转发连接
type RelayDetector interface {
    IsForwardedRelay(conn net.Conn, isFakeIP bool, pid int) bool
}
```

### 2.4 DNS 报文劫持器 `DNSHijacker`
位于 `internal/dns`，收敛跨平台 DNS 报文处理：
```go
func HijackPacket(raw []byte) (resp []byte, domain string, handled bool)
```

---

## 3. Acceptance Criteria (BDD)

### Feature: 统一驱动工厂与生命周期契约

#### Scenario 1: [SPEC-DRIVER-001] 驱动工厂在当前平台返回对应 Driver 实例
- **Given** vproxy 编译并运行在目标操作系统上
- **When** 调用 `driver.GetDefaultDriver(cfg)`
- **Then** 在 Linux 下返回 `LinuxDriver`（TUN 或 eBPF）
- **And** 在 Windows 下返回 `WindowsDriver`
- **And** 在 Darwin 下返回 `DarwinDriver`
- **And** 实例实现统一的 `InterceptDriver` 接口，支持标准 `Start` 与 `Cleanup`

---

### Feature: 进程归属探测器与显式能力契约

#### Scenario 2: [SPEC-DRIVER-002] 统一进程探测与显式不支持契约
- **Given** 核心处理层需要提取连接所属进程
- **When** 调用 `inspector.GetProcessNameByConn(conn)`
- **Then** 在 Windows / macOS 上提取出合法进程名与 PID
- **And** 在未支持的平台上（如当前 Linux）显式返回 `ErrProcessInspectionUnsupported`
- **And** 核心层不再需要硬编码 `runtime.GOOS == "darwin" || runtime.GOOS == "windows"`

---

### Feature: 核心层解耦与平台分支清除

#### Scenario 3: [SPEC-DRIVER-003] ProxyHandler 与 App 中消除平台分支
- **Given** `ProxyHandler.StartTransparent` 启动透明代理
- **When** 核心逻辑执行启动流程
- **Then** 直接调用 `ph.driver.Start(ctx, onTCP, onUDP)`
- **And** `StartTransparent` 内部无任何 `if runtime.GOOS == ...` 硬编码分支
- **And** `forward` 处理流程统一调用 `inspector` 和 `relayDetector`

---

### Feature: DNS 管道统合

#### Scenario 4: [SPEC-DRIVER-004] 统一 DNSHijacker 管道处理跨平台 DNS 报文
- **Given** 任意驱动（Windows Wintun / Linux TUN / Linux TPROXY UDP / Darwin PF）截获到 53 端口 UDP 报文
- **When** 送入 `dns.HijackPacket(raw)`
- **Then** 统一解析 A/AAAA 记录并分配 Fake-IP
- **And** 各平台驱动自身不包含重复的 DNS 解包与应答构造代码

---

### Feature: 统一环路检测

#### Scenario 5: [SPEC-DRIVER-005] 统一 RelayDetector 隔离平台特性
- **Given** 存在特定平台的本地中继环路场景（如 Windows WSL2）
- **When** 传输层处理连接时调用 `relayDetector.IsForwardedRelay(conn, isFakeIP, pid)`
- **Then** Windows 平台按 LUID 与私有网段检测环路
- **And** 非 Windows 平台默认返回 `false`，业务核心层无需硬编码 Windows 逻辑
