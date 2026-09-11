# Module Spec: L7 HTTP/HTTPS 请求重写引擎 (RewriteEngine)

## 1. Overview
本模块定义 `vproxy` 的 L7 应用层请求重写与本地反向代理引擎（`RewriteEngine`）。
该模块与现有的 L4 传输层分流规则（`rules`）彻底解耦，在配置文件中使用独立的 `rewrites` 字段。
支持类 Whistle 语法：
- 正则表达式替换（`/pattern/ target`），支持自动拼接原 URL 路径以及 `$1`, `$2` 捕获组变量回填；
- 通配符替换（`pattern/* target/$1`）；
- 本地静态文件 Mock（`file://...`）；
- 跨协议反向代理（HTTPS 入站解密后转发给本地 HTTP 服务，或 HTTP 转发给 HTTPS）；
- 采用 **方案 2（Host 预筛选分桶索引）**：在规则编译时静态提取目标域名，在请求时根据 `req.Host` 快速索引对应规则列表，实现无关请求对正则匹配的 $O(1)$ 级别零损耗跳过；
- 自动为 `rewrites` 中涉及的域名注册 HTTPS MITM 拦截名单，无需用户在 `rules` 中重复配置 `INTERCEPT`。

## 2. Interface / API Contract

### 数据模型
- **`Config.Rewrites []string`**: 配置文件中顶级字段，存放重写规则字符串列表。
- **`RewriteRule`**:
  - `Raw: string`
  - `Type: RewriteType` (Regex, Wildcard, Exact)
  - `Host: string` (提取的专属 Host，若为空则归入全局通配桶)
  - `Regex: *regexp.Regexp` (编译后的正则对象)
  - `Target: string` (重写目标：`http://...`, `https://...`, `file://...`)
- **`RewriteEngine`**:
  - `NewRewriteEngine(entries []string) (*RewriteEngine, error)`
  - `Match(reqURL string, host string) (*RewriteResult, bool)`
  - `GetInterceptHosts() []string`: 提取所有需触发 MITM 的域名列表，供握手阶段快速查询。

### 行为规则
1. **Host 预过滤分桶**：
   - 包含明确域名特征的规则（如 `/cafe123.cn\/.../` 或 `https://api.com/*`）被分发到 `hostBuckets[host]` 中。
   - 请求到达时，根据 `req.Host` 仅查询对应的 Bucket。若未命中任何专用桶且不存在全局桶，直接短路跳过，耗时为哈希查找级别。
2. **目标 URL 路径处理契约**：
   - 若目标无子路径（如 `http://127.0.0.1:3000`）且规则未包含捕获变量 `$1`，自动将原始请求的 `Path + Query` 拼接到目标末尾。
   - 若目标包含 `$1`, `$2` 等变量，使用正则捕获组（Submatches）进行精准参数展开。
3. **跨协议反向代理契约**：
   - 当入站请求为 HTTPS、目标为 `http://...` 时，引擎终结 TLS 并通过 HTTP 客户端转发给本地服务，同时自动注入 `X-Forwarded-Proto: https` 和 `X-Forwarded-Host`。

---

## 3. Acceptance Criteria (BDD)

### Feature: 规则解析与 Host 预过滤分桶

#### Scenario 1: [SPEC-REWRITE-001] 正则规则解析与 Host 桶自动归类
- **Given** 规则配置为 `["/cafe123.cn\\/.*?\\.(html|js|css|png|jpg)/ http://127.0.0.1:3000"]`
- **When** 调用 `NewRewriteEngine` 初始化
- **Then** 正则成功编译，且提取出专用 Host `cafe123.cn`
- **And** 该规则被索引至 `hostBuckets["cafe123.cn"]`
- **And** 调用 `GetInterceptHosts()` 返回包含 `cafe123.cn`

#### Scenario 2: [SPEC-REWRITE-002] 无关 Host 零正则损耗（方案 2 验证）
- **Given** 引擎仅加载了针对 `cafe123.cn` 的若干复杂正则规则
- **When** 收到针对 `github.com` 的请求调用 `Match("https://github.com/index.html", "github.com")`
- **Then** 引擎直接基于 `Host` 桶快速返回未命中，不执行任何正则比对

---

### Feature: URL 替换与变量展开

#### Scenario 3: [SPEC-REWRITE-003] 正则匹配并自动追加请求路径 (Auto Path Append)
- **Given** 规则为 `/cafe123.cn\/.*?\.(js|css)/ http://127.0.0.1:3000`
- **When** 请求 `https://cafe123.cn/assets/app.js?v=2`
- **Then** `Match` 判定命中
- **And** 计算出的重写目标为 `http://127.0.0.1:3000/assets/app.js?v=2`

#### Scenario 4: [SPEC-REWRITE-004] 捕获组变量回填 ($1 展开)
- **Given** 规则为 `/api.example.com\/v1\/(.*)/ http://127.0.0.1:8080/v2/$1`
- **When** 请求 `https://api.example.com/v1/user/info?id=10`
- **Then** `Match` 判定命中
- **And** 计算出的重写目标为 `http://127.0.0.1:8080/v2/user/info?id=10`

#### Scenario 5: [SPEC-REWRITE-005] 通配符 `*` 路径替换
- **Given** 规则为 `https://api.prod.com/service/* http://127.0.0.1:9000/$1`
- **When** 请求 `https://api.prod.com/service/pay/order`
- **Then** `Match` 判定命中，目标展开为 `http://127.0.0.1:9000/pay/order`

---

### Feature: 本地 Mock 与多协议适配

#### Scenario 6: [SPEC-REWRITE-006] 本地文件 Mock (`file://`)
- **Given** 规则为 `https://api.prod.com/config file:///tmp/config.json`
- **When** 请求 `https://api.prod.com/config`
- **Then** `Match` 判定命中，返回 Action 为 Mock，目标文件路径为 `/tmp/config.json`

#### Scenario 7: [SPEC-REWRITE-007] HTTPS 到 HTTP 的跨协议反向代理
- **Given** 客户端通过 HTTPS 向 `vproxy` 发起请求并命中重写规则指向 `http://127.0.0.1:3000`
- **When** 反向代理处理器执行转发
- **Then** 成功剥离 TLS 并以 HTTP 明文请求打到本地 `3000` 端口
- **And** 注入请求头 `X-Forwarded-Proto: https`
- **And** 客户端成功接收到返回的响应内容
