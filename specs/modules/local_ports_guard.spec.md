# Module Spec: Local Proxy Ports & Upstream Self-Loop Protection

## 1. Overview
本模块定义了 `vproxy` 本地辅助代理服务（SOCKS5 / HTTP）的端口管理、按需监听机制以及上游自回环防护策略：
1. **默认禁用本地 SOCKS5 服务**：`localSocks` 默认端口设为 `0`（不启动监听）。透明代理（TUN / eBPF）模式下不再占用 `127.0.0.1:1080`，避免与系统已有的代理客户端（如 Clash、Shadowsocks、Xray 等）冲突，亦杜绝自连接死循环。只有当命令行明确传入 `-socks <port>` 或配置文件中指定非零 `socks_port` 时才开启监听。
2. **配置文件支持端口控制**：在 `vproxy.json` 配置根对象中引入 `socks_port` 与 `http_port` 可选字段。
3. **上游自回环主动防御（Self-Loop Prevention）**：`ServerManager` 与拨号模块对上游列表进行自环检测。若某上游地址指向 `vproxy` 自身正在监听的本地端口（如自身开启的 SOCKS/HTTP/Trans 端口），自动过滤并记录警告日志，防止因错误配置造成无限自连重试和假死。
4. **透明代理 SNI 嗅探域名同步**：修复在 HTTPS 透明代理未通过 Fake-IP 命中时，SNI 恢复域名后局部 `host` 变量未同步更新的 Bug，确保后续 `MatchContext` 精确匹配域名规则。

## 2. Interface / API Contract

### 2.1 Configuration Schema (`internal.Config`)
```go
type Config struct {
    Upstreams      []string `json:"upstreams"`
    Rules          []string `json:"rules"`
    TestInterval   int      `json:"test_interval"`
    WebPort        int      `json:"web_port,omitempty"`
    SocksPort      *int     `json:"socks_port,omitempty"` // 默认 nil/0，<= 0 表示不启动
    HttpPort       *int     `json:"http_port,omitempty"`  // 默认 nil/8118
    EnableEbpf     *bool    `json:"enable_ebpf,omitempty"`
    DirectDNS      *bool    `json:"direct_dns,omitempty"`
    DialTimeoutMs  *int     `json:"dial_timeout_ms,omitempty"`
    DialRetryCount *int     `json:"dial_retry_count,omitempty"`
    BypassNodes    []string `json:"bypass_nodes,omitempty"`
    Rewrites       []string `json:"rewrites,omitempty"`
}
```

### 2.2 CLI Flags
- `-socks`: 默认值由 `1080` 改为 `0`。当值为 `<= 0` 时跳过 SOCKS5 监听。
- `-http`: 默认值保持 `8118`，当值为 `<= 0` 时跳过 HTTP 代理监听。

### 2.3 Handlers & ServerManager
- `ProxyHandler.StartSocks()`: 若 `ph.SocksPort <= 0`，立即返回 `nil`，不分配 socket 与 goroutine。
- `ProxyHandler.StartHTTP()`: 若 `ph.HttpPort <= 0`，立即返回 `nil`。
- `ServerManager.FilterSelfUpstreams(selfPorts []int)`: 过滤并标记命中自身监听端口的上游节点。

---

## 3. Acceptance Criteria (BDD)

### Feature 1: Disable Local SOCKS5 by Default

#### Scenario 1: [SPEC-PORT-001] 默认启动不开启本地 SOCKS5
- **Given** 启动参数未指定 `-socks` 且配置文件未配置 `socks_port`
- **When** 调用 `vproxy start` 或初始化核心服务 `ph.StartSocks()`
- **Then** `ph.socksLn` 为 `nil`，不占用任何本地端口，`ph.StartSocks()` 正常返回且不报错。
- **Mapped Test:** `internal/config_test.go:TestSocksDefaultDisabled`

#### Scenario 2: [SPEC-PORT-002] 显式指定端口时启动 SOCKS5
- **Given** 配置文件声明 `"socks_port": 10808` 或 CLI 参数 `-socks 10808`
- **When** 启动代理服务
- **Then** `ph.SocksPort` 为 10808，本地成功监听 `127.0.0.1:10808`。
- **Mapped Test:** `internal/config_test.go:TestSocksExplicitPort`

### Feature 2: Upstream Self-Loop Protection

#### Scenario 3: [SPEC-PORT-003] 上游包含自身监听端口时主动剔除
- **Given** 本地正在监听 `SocksPort = 10808`，且配置文件误配了 `"socks5://127.0.0.1:10808"`
- **When** `ServerManager` 探测或初始化可用上游
- **Then** 识别出自回环节点，跳过握手探测，不得将自身选为 `activeServer`。
- **Mapped Test:** `internal/servermanager_test.go:TestUpstreamSelfLoopDetection`

### Feature 3: SNI Recovery Host Synchronization

#### Scenario 4: [SPEC-PORT-004] SNI 嗅探成功后同步更新 host 上下文
- **Given** 目标以裸 IP `1.2.3.4:443` 接入透明代理且 Fake-IP 缓存未命中
- **When** 成功通过 SNI 提取出 `oauth2.googleapis.com`
- **Then** `target` 更新为 `oauth2.googleapis.com:443`，且传给 `rm.MatchContext` 的 `Host` 必须为 `oauth2.googleapis.com` 而非原始 IP。
- **Mapped Test:** `internal/handler_test.go:TestSNIHostSyncInMatchContext`
