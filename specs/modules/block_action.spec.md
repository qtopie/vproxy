# SPEC-BLOCK — 流量阻断规则动作

**版本：** v1.0 (已批准)
**状态：** ✅ Approved
**编号：** SPEC-BLOCK-001 ~ SPEC-BLOCK-005
**依赖规格：** 现有路由体系 (router.go)、handler 动作分发、SPEC-OTEL-007

---

## 1. 背景与目标

vproxy 当前支持 `DIRECT` / `PROXY` / `INTERCEPT` / `MAP` 四种路由动作。
新增 **`BLOCK`** 动作，使运营者能精确拒绝某类流量的网络访问，而无需依赖上游防火墙。

**典型场景：**
- `PROCESS,curl,BLOCK` — 阻断 curl 进程的所有出站连接
- `DOMAIN,facebook.com,BLOCK` — 阻断对 facebook.com（含子域名）的访问
- `IP_CIDR,0.0.0.0/0,BLOCK` + `IP_CIDR,192.168.0.0/16,DIRECT` — 阻断所有外网（保内网）
- `FINAL,BLOCK` — 默认拒绝所有未匹配流量

---

## 2. 规则语法规格

### SPEC-BLOCK-001 — ActionBlock 常量

在 `internal/router.go` 的 `RuleAction` iota 中增加（排在 ActionMap 之后）：

```go
ActionBlock RuleAction = iota
```

`String()` 方法返回 `"BLOCK"`；`default` 分支保持 `"DIRECT"`（向后兼容）。

### SPEC-BLOCK-002 — 新增 RuleTypeIPCIDR

在 `RuleType` iota 中增加：

```go
RuleTypeIPCIDR RuleType = iota
```

**匹配语义：** 对 `ctx.Host` 调用 `net.ParseIP` 解析；解析成功则与规则 `CIDR *net.IPNet` 做 `Contains` 检查。
CIDR 格式非法时打印 Warn 日志并跳过该规则，不 panic。

**已知限制（V1）：** 对域名 ctx.Host 不做反查，CIDR 规则仅对裸 IP 目标生效。

### SPEC-BLOCK-003 — 规则字符串解析

配置文件新增以下格式（大小写不敏感）：

| 格式 | 说明 |
|---|---|
| `DOMAIN,facebook.com,BLOCK` | 阻断指定域名（含子域） |
| `PROCESS,curl,BLOCK` | 阻断指定进程（名字含匹配，大小写不敏感） |
| `IP_CIDR,10.0.0.0/8,BLOCK` | 阻断指定网段 |
| `IP_CIDR,0.0.0.0/0,BLOCK` | 阻断所有 IPv4 |
| `FINAL,BLOCK` | 将默认动作设为阻断 |

解析规则：`p0 == "IP_CIDR"` → `ruleType = RuleTypeIPCIDR`，CIDR 字符串存入 `Rule.CIDR`。

---

## 3. 匹配引擎扩展规格

### SPEC-BLOCK-004 — doMatchContext 中的 CIDR 匹配

`doMatchContext` step 3（遍历用户规则）中 `RuleTypeIPCIDR` case：

```go
case RuleTypeIPCIDR:
    ip := net.ParseIP(ctx.Host)
    if ip != nil && rule.CIDR != nil && rule.CIDR.Contains(ip) {
        return rule.Action, rule.Target
    }
```

`Rule` 结构体新增字段 `CIDR *net.IPNet`，由 `NewRuleManager` 解析时填充。

**优先级：** 按配置文件顺序线性扫描，先命中先返回。推荐：PROCESS 规则置顶，IP_CIDR 置底。

---

## 4. 执行语义规格

### SPEC-BLOCK-005 — 各入口点的 BLOCK 执行行为

#### 4.1 TUN/透明代理 `forward(conn, target)`

在 `doMatchContext` 调用后、relayDetector 检查前插入：

```go
if action == ActionBlock {
    TraceInfof(ctx, "[BLOCK] Rejected %s -> %s (process: %s)", conn.RemoteAddr(), target, process)
    if sessionSpan != nil {
        sessionSpan.SetStatus(codes.Error, "blocked by policy")
    }
    conn.Close()
    return
}
```

TCP 连接静默关闭（RST），客户端收到 connection reset。

#### 4.2 dialTarget（SOCKS5 / TUN 拨号）

```go
if action == ActionBlock {
    return nil, fmt.Errorf("BLOCK: connection to %s rejected by policy", target)
}
```

#### 4.3 dialTargetUDP

```go
if action == ActionBlock {
    return nil, fmt.Errorf("BLOCK: UDP to %s rejected by policy", target)
}
```

#### 4.4 HTTP 代理 CONNECT 入口

在 `action, _ := ph.rm.MatchContext(...)` 之后、MITM 分支之前插入：

```go
if action == ActionBlock {
    fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nX-Block-Reason: policy\r\nContent-Length: 0\r\n\r\n")
    return
}
```

#### 4.5 Plain HTTP 入口（forwardPlainHTTPRequest）

`forwardPlainHTTPRequest` 调用 `dialTarget`，`dialTarget` 已返回 error，上层回写 502；
为提供更准确的 403，在进入 `forwardPlainHTTPRequest` 前添加检查（在 handler 调用处）：

```go
if action == ActionBlock {
    res := &http.Response{StatusCode: http.StatusForbidden, ...}
    res.Write(conn)
    return
}
```

#### 4.6 OTel Span 行为

`matchedRuleAction = action.String()` 已自动为 `"BLOCK"`，OTel 属性 `rule.action="BLOCK"` 无需额外代码。

---

## 5. 日志规格

| 场景 | 级别 | 格式 |
|---|---|---|
| 连接被 BLOCK | `Info` | `[BLOCK] %s -> %s (process: %s, rule: %s)` |
| CIDR 解析失败 | `Warn` | `Router: invalid CIDR %q in rule %q, skipping` |

---

## 6. 测试规格

文件：`internal/router_block_test.go`

| 用例 | 预期 |
|---|---|
| DOMAIN BLOCK 精确匹配 | ActionBlock |
| DOMAIN BLOCK 子域名匹配 | ActionBlock |
| PROCESS BLOCK 精确匹配 | ActionBlock |
| PROCESS BLOCK 路径含匹配 | ActionBlock |
| IP_CIDR BLOCK 命中 | ActionBlock |
| IP_CIDR 顺序：内网DIRECT先于0/0 BLOCK | ActionDirect |
| FINAL,BLOCK 默认阻断 | ActionBlock |
| IP_CIDR 非法格式 | 跳过，后续规则正常 |
| PROCESS BLOCK + DOMAIN PROXY 联合 | ActionBlock (PROCESS 先) |

---

## 7. 不在 V1 范围

- DNS 层 BLOCK（NXDOMAIN 注入）
- HTTP 响应体自定义拦截页
- BLOCK 计数器/Metrics OTel metric 暴露
