# Module Spec: Fluent UI + React + TypeScript 前端重构 (FluentUI Frontend)

## 1. Overview
本模块定义 `vproxy` Web 管理与调试界面的现代化重构方案。
将此前嵌入在 Go 后端源码中硬编码的原生 HTML/CSS 单文件（`internal/web.go:indexHTML`），在 `frontend/` 目录下全面重构为基于 **Microsoft Fluent UI v9**、**React** 与 **TypeScript** 的现代单页应用（SPA）。

### 核心设计目标
1. **现代化 UI 体系**：采用 Microsoft Fluent UI v9 (`@fluentui/react-components`) 设计语言，原生支持 FluentProvider 亮色/暗色主题无缝切换、标准化设计令牌（Design Tokens）与响应式布局。
2. **深度抓包监控台 (HTTP/HTTPS Deep Tracing)**：
   - 基于 Fluent DataGrid 提供可排序、可过滤、可检索的高性能请求列表。
   - 抽屉式（Drawer/Overlay）请求与响应详情面板：展示格式化 Headers、格式化 JSON Body、状态码胶囊与延迟指示器。
   - 内置“一键复制 cURL”与“请求回放模板生成”功能。
3. **路由分流与 L7 重写可视化管理**：
   - 直观管理 `rules`（DOMAIN, PROCESS, IP_CIDR 等）与 `rewrites`（URL 重写与本地 Mock）。
   - 提供可视化表单卡片编辑与高级原始 JSON 编辑器双向无损切换。
   - 高级原始 JSON 编辑器采用 Monaco Editor (`@monaco-editor/react`)，支持 VS Code 级别的 JSON 语法高亮、语法校验、行号与折叠，并与 Fluent UI 亮暗主题无缝联动。
   - 通过 `/api/config` 实时保存并热生效（Hot-Reload）。
4. **Go 后端集成契约**：
   - 生产构建产物输出至 `frontend/dist/`。
   - Go 后端（`internal/web.go`）动态探测 `frontend/dist/` 并提供静态资源托管与 SPA Fallback 路由；若未构建则自动平滑降级至精简版兜底页。

---

## 2. Interface / API Contract

### 后端 API 接口契约
* `GET /api/traces`: 获取当前内存中捕获的 HTTP/HTTPS 跟踪列表，返回 `[]TraceEntry`。
* `GET /api/config`: 获取当前生效的 `Config` JSON 配置。
* `POST /api/config`: 提交新的 `Config` JSON，由后端保存至磁盘并热重载路由与重写规则。

### 前端 TypeScript 数据模型
```typescript
export interface TraceEntry {
  id: string;
  timestamp: string;
  method: string;
  url: string;
  path: string;
  host: string;
  request_proto: string;
  req_headers: Record<string, string[]>;
  req_body?: string;
  status_code: number;
  resp_headers: Record<string, string[]>;
  resp_body?: string;
  latency_ms: number;
}

export interface VProxyConfig {
  upstreams: string[];
  rules: string[];
  test_interval?: number;
  web_port?: number;
  socks_port?: number;
  http_port?: number;
  enable_ebpf?: boolean;
  direct_dns?: boolean;
  dial_timeout_ms?: number;
  dial_retry_count?: number;
  bypass_nodes?: string[];
  rewrites?: string[];
  otel?: {
    enabled: boolean;
    endpoint: string;
    protocol?: string;
    insecure?: boolean;
    service_name?: string;
    sample_rate?: number;
  };
}
```

---

## 3. Acceptance Criteria (BDD)

### Feature: Fluent UI 应用外壳与主题体系

#### Scenario 1: [SPEC-FRONTEND-001] 主题切换与 FluentProvider 包装
- **Given** 用户通过浏览器访问 Web 管理页面
- **When** 页面初始化或用户点击顶栏主题切换按钮（Sun/Moon 图标）
- **Then** 全局应用根据状态在 `webLightTheme` 与 `webDarkTheme` 之间切换
- **And** 侧边栏导航、卡片底色、文字对比度与 Fluent 令牌保持统一
- **Mapped Test:** `frontend/src/__tests__/App.test.tsx:TestThemeToggle`

---

### Feature: Deep Tracing 抓包监控与检索

#### Scenario 2: [SPEC-FRONTEND-002] 实时请求列表渲染与搜索过滤
- **Given** 后端接口 `/api/traces` 返回若干抓包记录
- **When** 用户在搜索框中输入关键字（如域名 `loreal-boutique.com`）或选择状态码过滤（如 `2xx`, `4xx`）
- **Then** DataGrid 仅展示符合条件的记录，并高亮显示 Method Badge 与状态指示
- **And** 支持开启/暂停自动轮询（1s / 3s / 5s 自动刷新）
- **Mapped Test:** `frontend/src/__tests__/TracesView.test.tsx:TestTracesFilter`

#### Scenario 3: [SPEC-FRONTEND-003] 详情抽屉与 cURL 回放生成
- **Given** 用户在抓包列表中选中一条请求
- **When** 点击该行打开详情抽屉（Drawer）
- **Then** 分页展示 Request Headers, Request Body, Response Headers, Response Body
- **And** 点击“Copy as cURL”按钮能根据当前请求 Method、URL、Headers 及 Body 正确生成完整的 cURL 命令到剪贴板
- **Mapped Test:** `frontend/src/__tests__/TraceDetail.test.tsx:TestCurlExport`

---

### Feature: 配置与规则可视化管理

#### Scenario 4: [SPEC-FRONTEND-004] 路由与重写规则可视化编辑与保存
- **Given** 用户切换至“Rules & Config”视图
- **When** 用户新增一条 `DOMAIN,example.com,INTERCEPT` 规则或修改 `rewrites` 并点击“保存并应用”
- **Then** 前端向 `/api/config` 发起 POST 请求提交有效配置
- **And** 保存成功后页面弹出 Fluent UI MessageBar 提示保存成功，若 JSON 语法错误则拦截提交并提示
- **Mapped Test:** `frontend/src/__tests__/ConfigView.test.tsx:TestConfigSave`

#### Scenario 6: [SPEC-FRONTEND-006] Raw JSON 视图采用 Monaco Editor
- **Given** 用户在配置管理页切换至“Raw JSON”标签页
- **When** Monaco Editor 挂载完成
- **Then** 编辑器以 JSON 语言模式渲染当前完整配置，具备原生代码高亮、行号、折叠与格式化功能
- **And** 编辑器主题根据当前全局主题动态切换（浅色模式为 `vs`，深色模式为 `vs-dark`）
- **And** 用户编辑后点击“Save & Hot Reload Config”，若 JSON 解析有效则成功提交至 `/api/config`；若无效则提示错误并阻止提交
- **Mapped Test:** `frontend/src/__tests__/ConfigView.test.tsx:TestMonacoJsonEditor`

---

### Feature: Go 服务端构建集成与静态托管

#### Scenario 5: [SPEC-FRONTEND-005] SPA 静态资源托管与回退
- **Given** `frontend/` 执行 `npm run build` 生成 `frontend/dist/`
- **When** 启动 vproxy 并访问 `http://127.0.0.1:<web_port>/`
- **Then** 后端 `internal/web.go` 正确响应 `frontend/dist/index.html` 及静态 js/css 资源
- **And** 若访问不存在的路由路径，正确返回 `index.html`（SPA Fallback）
- **And** 若 `frontend/dist/` 目录不存在，平滑降级提供内置简易 HTML，不抛出 Panic
- **Mapped Test:** `internal/web_test.go:TestWebServerStaticDistFallback`
