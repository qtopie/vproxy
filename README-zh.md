# vproxy - 高性能透明代理与封装工具

`vproxy` 是一个用 Go 编写的高性能、轻量级多平台透明代理服务器和封装工具。它能够无缝重定向任何应用程序的网络流量（TCP 和 UDP），无需对应用程序进行任何配置。

## ✨ 核心特性

- **高性能 eBPF 重定向**：在 Linux 上利用 eBPF 技术实现极致的内核级转发。
- **完全透明**：无需设置环境变量（如 `HTTP_PROXY`），支持所有原生应用。
- **安全可靠**：采用 IPC 通信机制实现无权限（Unprivileged）进程的 cgroup 自动迁移。
- **智能分流**：支持基于域名、IP CIDR 和进程名的灵活规则配置。
- **多平台支持**：支持 Linux (eBPF/Iptables), macOS, 和 Windows。

## 🚀 快速开始

### 1. 安装与初始化 (Linux)

你可以从 [Releases](https://github.com/qtopie/vproxy/releases) 下载对应平台的压缩包，解压后执行初始化：

```bash
# 初始化环境（设置 eBPF 权限并启动后台服务）
sudo vproxy init
```

#### systemd 服务配置

为了让 `vproxy` 在系统启动时自动运行，且在退出或崩溃后自动重启，可以配置为 `systemd` 服务。

在 `/etc/systemd/system/vproxy.service` 中写入以下配置（注意将 `SUDO_USER` 修改为你日常使用的普通用户名，以便非 root 进程能正常执行 cgroup 迁移）：

```ini
[Unit]
Description=vproxy Transparent Proxy Server
After=network.target

[Service]
Type=forking
PIDFile=/tmp/vproxy.pid
Environment=SUDO_USER=your_username
ExecStartPre=/usr/local/bin/vproxy clean
ExecStart=/usr/local/bin/vproxy -c /etc/vproxy/config.json init
ExecStop=/usr/local/bin/vproxy clean
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

然后，执行以下命令来启用并启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable vproxy
sudo systemctl start vproxy
```

### 2. 基础用法

#### 场景 A：透明代理整个终端会话
你可以通过 `attach` 命令将当前终端的所有流量永久接入代理：

```bash
vproxy attach
# 现在该窗口下的所有命令（curl, git, wget 等）都会走代理
curl -v https://google.com
```

#### 场景 B：封装单个命令执行
仅针对特定命令开启代理拦截：

```bash
vproxy curl -v https://google.com
```

### 3. 配置文件

在 Linux 下，默认的全局配置文件位于 `/etc/vproxy/config.json`。你可以通过编辑此文件来配置上游服务器和分流规则：

```json
{
  "upstreams": ["socks5://127.0.0.1:1080"],
  "rules": [
    "8.8.8.8,DIRECT",
    "google.com,PROXY",
    "FINAL,PROXY"
  ],
  "enable_ebpf": true
}
```

## 🚧 未来计划

- **抓包与流量分析**：集成类似 [whistle](https://github.com/avwo/whistle) 的功能，支持实时抓包、修改请求/响应内容、数据 Mock 等。
- **Web UI 控制台**：提供直观的流量监控与规则管理界面。
- **更强的协议支持**：持续优化对 HTTP/2, gRPC 以及 QUIC 的透明拦截能力。

## 🛠️ 开发与构建

项目使用 [Taskfile](https://taskfile.dev/) 进行任务管理：

```bash
# 生成 eBPF 资源
task generate

# 编译主程序
task default

# 运行测试
task test-network
```

---

更多详细设计请参考 [英文 README](README.md)。
