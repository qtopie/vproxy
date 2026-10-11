# Module Spec: 路由规则禁用/注释状态与可视化切换 (Inactive Rules & Toggle)

## 1. Overview
在日常网络代理与抓包排查中，用户常需要临时停用某些路由规则（如 `INTERCEPT`、`PROXY` 或 `BLOCK`），但又希望保留其配置以便随时恢复，避免频繁删除与重复输入。
本模块定义路由规则的 Inactive（非活跃/注释）标记契约，涵盖后端核心路由解析忽略与前端 Fluent UI 可视化 Switch 切换与展示。

### 核心设计原则
1. **零运行时开销**：Inactive 规则被后端加载时直接跳过，不占用路由匹配索引，不参与流量拦截。
2. **非破坏性存储**：规则在 `config.json` 中以带前缀的字符串形式保存，完整保留在 `rules` 数组内。
3. **人类可读与标准习惯**：默认采用网络工具事实标准 `#` 作为注释/禁用前缀，兼容 `//` 与 `DISABLED,`。
4. **前端一键切换**：前端提供 Switch 开关，支持即时切换规则的活跃/非活跃状态并触发热重载，同时以置灰样式清晰指示。

---

## 2. Interface & Syntax Contract

### 规则前缀定义
* **Inactive 前缀**：
  * `#`（推荐标准，如 `#DOMAIN,example.com,INTERCEPT`、`#192.168.0.0/16,DIRECT`）
  * `//`（如 `//PROCESS,curl,PROXY`）
  * `DISABLED,`（不区分大小写，如 `DISABLED,DOMAIN,example.com,BLOCK`）
* **解析判定**：
  * 去除首尾空白后，若字符串以 `#` 或 `//` 或 `DISABLED,`（大小写无关）开头，均判定为 `Inactive` 规则。

---

## 3. Acceptance Criteria (BDD)

### Feature: 后端规则解析跳过与流量路由

#### Scenario 1: [SPEC-INACTIVE-001] 后端解析跳过 Inactive 规则
- **Given** 配置中包含带 `#`、`//` 或 `DISABLED,` 前缀的规则条目
- **When** `NewRuleManager` 初始化或热更新重载规则表
- **Then** 所有带 Inactive 前缀的条目被跳过，不生成 `Rule` 对象加入路由列表
- **And** 不带前缀的正常规则正常解析并生效
- **Mapped Test:** `internal/router_test.go:TestNewRuleManager_InactiveRulesIgnored`

#### Scenario 2: [SPEC-INACTIVE-002] Inactive 规则不影响后续规则匹配与兜底
- **Given** 配置存在 `#DOMAIN,google.com,PROXY` 及后续生效的 `FINAL,DIRECT`
- **When** 收到目标为 `google.com:443` 的请求进行路由匹配
- **Then** 由于匹配项被禁用，请求未被 PROXY 匹配，顺利落入 `FINAL,DIRECT`
- **Mapped Test:** `internal/router_test.go:TestRuleManager_InactiveRuleFallback`

---

### Feature: 前端状态展示与 Switch 切换

#### Scenario 3: [SPEC-INACTIVE-003] 前端解析与置灰渲染 Inactive 规则
- **Given** 后端返回的 `config.rules` 包含带 `#` 前缀的禁用规则
- **When** 用户进入“Rules & Routing”页面
- **Then** 前端准确识别该规则为非活跃状态，Switch 呈关闭状态，行项目呈现半透明与灰色 Badge
- **And** 列表顶部统计展示当前 Active 与 Inactive 规则数量
- **Mapped Test:** `frontend/src/__tests__/config.test.ts:TestInactiveRuleParsing`

#### Scenario 4: [SPEC-INACTIVE-004] 前端 Switch 开关切换与无损保存
- **Given** 列表中存在一条活跃规则 `DOMAIN,test.com,INTERCEPT`
- **When** 用户点击该条规则的 Switch 开关将其关闭
- **Then** 前端将该规则字符串更新为 `#DOMAIN,test.com,INTERCEPT` 并发起保存请求
- **When** 用户再次点击 Switch 开关将其开启
- **Then** 前端去除 `#` 前缀恢复为 `DOMAIN,test.com,INTERCEPT` 并发起保存请求
- **Mapped Test:** `frontend/src/__tests__/config.test.ts:TestRuleTogglePrefix`
