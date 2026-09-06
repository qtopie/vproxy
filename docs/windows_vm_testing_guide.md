# Windows 虚拟机自动化测试环境搭建与操作指南

本指南记录了在 Linux 宿主机上基于 **QEMU/KVM** 与 **QEMU Guest Agent** 搭建全自动、无感控制 Windows 虚拟机进行 `vproxy`（TUN 模式、Wintun 驱动、Fake-IP 劫持及进程匹配）测试的完整方案。

---

## 1. 方案背景与核心优势

在开发和测试底层网络代理（尤其是涉及 Wintun 驱动、全局路由注入 `0.0.0.0/1`、DNS 劫持及防环路 `IP_UNICAST_IF`）时，传统的 SSH/RDP/WinRM 方案存在明显痛点：
- **致命痛点**：若测试过程中代理异常或路由清理失败，虚拟机的 TCP/IP 网络会中断，导致 SSH / WinRM 彻底失联，必须人工到图形界面重置。
- **本方案优势（QEMU Guest Agent）**：
  - **基于底层串口通道 (`virtio-serial`)**：通信完全独立于 TCP/IP 网络。即使 Windows 彻底断网、路由损坏，宿主机仍能 100% 稳定下发命令并收集日志。
  - **毫秒级远程执行**：宿主机直接调用 PowerShell 脚本并获取标准输出与退出码。
  - **全自动化**：宿主机交叉编译、打包、推送、执行测试、清理环境一气呵成。

---

## 2. 宿主机环境配置 (Linux)

### 2.1 硬件与基础组件检查
确保已安装 QEMU/KVM 与 libvirt 管理工具：
```bash
sudo apt update
sudo apt install -y qemu-system-x86 libvirt-daemon-system libvirt-clients virt-manager
```

### 2.2 为虚拟机添加 Guest Agent 串口通道
在宿主机中为 Windows 虚拟机（以 `win11` 为例）挂载 `org.qemu.guest_agent.0` 设备：
```xml
<channel type="unix">
  <source mode="bind"/>
  <target type="virtio" name="org.qemu.guest_agent.0"/>
</channel>
```
挂载命令：
```bash
virsh attach-device win11 /path/to/channel.xml --config --live
```
> **提示**：如果虚拟机当前未开机，直接加 `--config` 参数即可在下次开机时自动生效。

---

## 3. Windows 虚拟机内配置 (仅需首次配置)

虚拟机需安装两样组件（均包含在官方 `virtio-win.iso` 驱动光盘中）：

1. **VirtIO 串口驱动 (vioserial)**：
   - 打开 Windows **设备管理器**。
   - 如果有未识别的串口或 PCI 通信设备，右键选择“更新驱动程序” -> 浏览到挂载的 `virtio-win` 光盘中选择 `vioserial\w11\amd64`（或对应系统架构）完成安装。
2. **QEMU Guest Agent 服务**：
   - 进入光盘的 `guest-agent\` 目录。
   - 双击运行 **`qemu-ga-x86_64.msi`** 完成安装。
   - 检查 Windows 服务 (`services.msc`)，确认 **QEMU Guest Agent** 服务已处于“正在运行”状态。

完成后重启一次虚拟机：
```bash
virsh reboot win11
```

---

## 4. 宿主机操控工具与自动化脚本

### 4.1 核心命令通道脚本 (`scripts/win_exec.py`)
我们在宿主机编写了封装脚本 `scripts/win_exec.py`，利用 `virsh qemu-agent-command` 下发 Base64 编码的 PowerShell 指令，并捕获执行结果与输出：

```bash
# 测试宿主机与 Windows 虚拟机的通信
virsh qemu-agent-command win11 '{"execute":"guest-ping"}'
# 正常应返回: {"return":{}}

# 远程执行任意 PowerShell 命令
python3 scripts/win_exec.py "Get-NetAdapter"
python3 scripts/win_exec.py "Get-NetRoute -DestinationPrefix '0.0.0.0/1'"
```

### 4.2 文件分发方案
在宿主机通过内置 HTTP 服务将编译好的产物供给虚拟机拉取：
```bash
python3 -m http.server 8080 --directory dist/
```
宿主机在虚拟网络桥（`virbr0`）上的网关 IP 通常是 `192.168.123.1`。
在虚拟机中执行下载仅需一条 PowerShell：
```powershell
Invoke-WebRequest -Uri "http://192.168.123.1:8080/vproxy_windows_bundle.zip" -OutFile "C:\vproxy_test\bundle.zip"
```

---

## 5. `vproxy` 测试工作流

### 5.1 宿主机编译与打包
```bash
# 1. 交叉编译 Windows amd64 二进制
mkdir -p dist
GOOS=windows GOARCH=amd64 go build -o dist/vproxy.exe ./cmd/vproxy

# 2. 准备官方 wintun.dll (WireGuard 团队发布)
curl -fsSL https://www.wintun.net/builds/wintun-0.14.1.zip -o /tmp/wintun.zip
unzip -q /tmp/wintun.zip -d /tmp/wintun
cp /tmp/wintun/wintun/bin/amd64/wintun.dll dist/wintun.dll

# 3. 准备测试配置文件与一键测试脚本
# 打包为 dist/vproxy_windows_bundle.zip
```

### 5.2 宿主机一键部署到 Windows
```bash
python3 scripts/win_exec.py '$ProgressPreference="SilentlyContinue"; New-Item -ItemType Directory -Path C:\vproxy_test -Force; Invoke-WebRequest -Uri "http://192.168.123.1:8080/vproxy_windows_bundle.zip" -OutFile "C:\vproxy_test\bundle.zip"; Expand-Archive -Path "C:\vproxy_test\bundle.zip" -DestinationPath C:\vproxy_test -Force'
```

### 5.3 启动与验证
通过宿主机直接调用 Windows 启动 `vproxy`：
```bash
python3 scripts/win_exec.py 'Set-Location C:\vproxy_test; Start-Process -FilePath ".\vproxy.exe" -ArgumentList "-c vproxy_test.json start" -RedirectStandardOutput ".\vproxy.log" -RedirectStandardError ".\vproxy_err.log"'
```

查看 Windows 端运行日志：
```bash
python3 scripts/win_exec.py 'Get-Content C:\vproxy_test\vproxy.log -Tail 30'
```

### 5.4 验证核心测试项
1. **Wintun 适配器创建**：
   ```bash
   python3 scripts/win_exec.py 'Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*Wintun*" }'
   ```
2. **路由劫持**：
   ```bash
   python3 scripts/win_exec.py 'Get-NetRoute -DestinationPrefix "0.0.0.0/1", "128.0.0.0/1"'
   ```
3. **Fake-IP 分配与域名还原**：
   ```bash
   python3 scripts/win_exec.py 'Resolve-DnsName google.com'
   ```
4. **进程匹配 (PROCESS-NAME)**：
   检查日志中是否捕获到诸如 `curl.exe` 或系统进程名及对应 PID。

---

## 6. 快照与灾备推荐 (Snapshot)

在 Windows 环境就绪后，建议在宿主机打一个基线快照：
```bash
virsh snapshot-create-as --domain win11 --name base_ready --description "Base system with QEMU GA ready"
```
若后续测试过程中系统路由被破坏，一键秒级回滚：
```bash
virsh snapshot-revert win11 base_ready
```
