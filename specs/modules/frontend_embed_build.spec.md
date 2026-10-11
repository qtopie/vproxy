# Module Spec: 前端内嵌编译、产物体积优化与 Taskfile 流水线 (Frontend Embed & Build Optimization)

## 1. Overview
本模块定义 `vproxy` 静态资源的编译分发、Go 二进制内嵌（`//go:embed`）、Vite 产物分包压缩以及 Taskfile 自动化构建流水线。
目标是实现**单一自包含可执行文件（Zero-Dependency Single Binary）**，在任何裸机环境下直接运行均内置完整的 Fluent UI + Monaco Editor 管理控制台，同时通过代码分包与按需加载确保最小打包体积与极速加载体验。

### 核心设计原则
1. **单一二进制自包含（Single Self-Contained Binary）**：
   - 采用 Go 1.16+ `//go:embed` 技术将前端产物编译进可执行文件。
   - 彻底摆脱对外部文件路径（如 `/usr/local/share/vproxy/...`）的硬性依赖，开箱即用。
2. **极速首屏与最小体积（Code Splitting & Minification）**：
   - Vite 采用 `manualChunks` 细粒度分包（`vendor-react`、`vendor-fluent`、`vendor-monaco`）。
   - Monaco Editor 与配置页通过 `React.lazy` + `Suspense` 异步按需加载，首页 Traces 监控极速加载。
   - Go 编译默认注入 `-ldflags="-s -w"` 剥离调试符号，缩减可执行文件 30%+ 体积。
3. **确定性构建流水线（Taskfile Automation）**：
   - `task build` 自动编排 `build-frontend` → `go build`。
   - `task release` 自动完成前端分包编译及 Linux / macOS / Windows 跨平台全架构打包。
4. **仅提交源码（Source-Only Commits）**：
   - `frontend/dist/` 构建产物不入库（`.gitignore` 保持忽略）。仅提交占位文件 `frontend/dist/.gitkeep`，保证 `//go:embed all:dist` 在未构建前端时也能通过编译（此时内嵌 FS 无 `index.html`，运行时回退到简易 HTML）。
   - 所有产出二进制的路径（`task build`、`task build-windows`、`task release`、CI release workflow）必须先执行 `task build-frontend`。

---

## 2. Architecture & File Structure

```
frontend/
├── dist/                  # Vite 生产构建产物
│   ├── index.html
│   └── assets/
│       ├── index-*.js     # 主入口与 TracesView
│       ├── vendor-react-*.js
│       ├── vendor-fluent-*.js
│       └── ConfigView-*.js (Monaco Editor 异步分包)
└── embed.go               # Go embed 包，暴露 DistFS()
```

---

## 3. Acceptance Criteria (BDD)

### Feature: Go 内嵌文件系统与静态服务

#### Scenario 1: [SPEC-EMBED-001] Go 二进制内嵌托管与平滑回退
- **Given** `frontend/dist` 已构建，`frontend/embed.go` 将其内嵌为 `embed.FS`
- **When** 启动独立编译的 vproxy 二进制并访问 `http://127.0.0.1:<web_port>/`
- **Then** Web 服务无需本地文件系统存在 `frontend/dist`，直接从二进制内嵌 FS 提供 `index.html` 与 JS/CSS 静态资产
- **And** 支持 SPA 客户端路由回退至内嵌 `index.html`
- **And** 若开发阶段显式通过 `SetFrontendDistDir` 指定外部目录，支持外部目录优先覆盖
- **Mapped Test:** `internal/web_test.go:TestWebServerEmbeddedDist`

---

### Feature: 前端代码分包与异步加载

#### Scenario 2: [SPEC-EMBED-002] Vite 代码分块与按需加载
- **Given** 前端项目在 `frontend/` 下执行 `npm run build`
- **When** Vite 完成打包
- **Then** `dist/assets/` 下生成独立的 vendor 模块与异步模块，单个主 bundle 体积严格小于 500 kB
- **And** `ConfigView` 与 Monaco Editor 依赖被抽离为异步代码块，首屏访问无需同步下载 Monaco 依赖
- **Mapped Test:** `frontend/src/__tests__/config.test.ts:TestBundleSplittingContract`

---

### Feature: Taskfile 自动化编译与跨平台发布

#### Scenario 3: [SPEC-EMBED-003] Taskfile 依赖驱动构建与 Release 编排
- **Given** 开发者或 CI 运行 `task build` 或 `task release`
- **When** 执行构建任务
- **Then** Taskfile 自动确保前端产物最新（`task build-frontend`），再执行 `go build`
- **And** 编译使用 `-ldflags="-s -w"` 产出经过符号裁剪的紧凑可执行文件
- **Mapped Test:** `harness/runners/spec_runner.sh:TestTaskfilePipeline`
