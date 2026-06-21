# 测试用例清单

本文档记录当前仓库里必须覆盖的网络与透明代理测试，重点验证：**当目标程序不支持 `https_proxy`、`socks_proxy` 等显式代理配置时，`vproxy` 仍能通过透明拦截并转发流量访问目标站点。**

## 前置准备

1. 编译主程序和测试二进制：

   ```bash
   timeout 120s make all
   timeout 120s make build-tests
   ```

2. 在执行任何 `vproxy` 相关测试前，先清理并初始化环境：

   ```bash
   timeout 120s bash -lc '
   if [ -f ~/.pass ]; then
       PASS=$(tr -d "\n" < ~/.pass)
       expect -c "
           set timeout 30
           spawn sudo bin/vproxy clean
           expect \"*Password:*\" { send \"$PASS\r\"; exp_continue }
           eof
       "
       expect -c "
           set timeout 30
           spawn sudo bin/vproxy init
           expect \"*Password:*\" { send \"$PASS\r\"; exp_continue }
           eof
       "
   else
       sudo bin/vproxy clean
       sudo bin/vproxy init
   fi
   '
   ```

## 必测用例

| 用例 | 目的 | 命令 | 通过标准 |
| --- | --- | --- | --- |
| 直连基线 | 确认宿主机本身具备基础外网访问能力，且测试程序不会读取环境代理变量。`tests/direct` 明确设置了 `http.Transport{Proxy:nil}`。 | `timeout 30s ./bin/test_direct` | 输出 `✅ Success!` |
| 上游代理连通性 | 确认本地 SOCKS5 上游可用，`vproxy` 后续转发有可达出口。 | `timeout 30s ./bin/test_upstream socks5://127.0.0.1:1080` | 输出 `✅ Success!` |
| 汇总网络冒烟 | 执行仓库内置的基础网络测试集合。 | `timeout 60s make test-network` | 直连与上游代理测试均成功 |
| eBPF 拦截 | 验证 eBPF/cgroup 拦截链路能把发往 `1.1.1.1:80` 的连接导入本地监听。Linux-only；非 Linux 平台允许输出 skip。 | `timeout 30s ./bin/test_ebpf` | Linux 下出现拦截成功日志；非 Linux 输出 skip |
| 原始目标提取 | 验证透明重定向后仍能从连接中恢复原始目标地址（`SO_ORIGINAL_DST`）。Linux-only；非 Linux 平台允许输出 skip。 | `timeout 30s ./bin/test_tproxy` | Linux 下出现 `✅ Extracted original destination`；非 Linux 输出 skip |
| 谷歌透明访问 | 核心场景。`tests/google` 默认 `TEST_MODE=transparent`，且不会使用 `https_proxy`/`socks_proxy` 环境变量；流量必须由 `vproxy` 拦截并转发。 | `timeout 30s bin/vproxy -v bin/test_google` | 输出 `✅ Connection Test Succeeded!`，目标为 `https://www.google.com` 或 `https://ipv6.google.com` |

## 推荐执行顺序

```bash
timeout 120s make all
timeout 120s make build-tests
timeout 120s bash -lc '
if [ -f ~/.pass ]; then
    PASS=$(tr -d "\n" < ~/.pass)
    expect -c "
        set timeout 30
        spawn sudo bin/vproxy clean
        expect \"*Password:*\" { send \"$PASS\r\"; exp_continue }
        eof
    "
    expect -c "
        set timeout 30
        spawn sudo bin/vproxy init
        expect \"*Password:*\" { send \"$PASS\r\"; exp_continue }
        eof
    "
else
    sudo bin/vproxy clean
    sudo bin/vproxy init
fi
'
timeout 60s make test-network
timeout 30s ./bin/test_ebpf
timeout 30s ./bin/test_tproxy
timeout 30s bin/vproxy -v bin/test_google
```

## 说明

- `make test-network` 目前只覆盖 `test_direct` 和 `test_upstream`，**不包含** `test_ebpf`、`test_tproxy`、`test_google`，所以三者必须额外执行。
- `bin/test_google` 支持以下环境变量，便于补充验证：
  - `TEST_PROTO=ipv4|ipv6`：强制验证 IPv4 或 IPv6。
  - `TEST_MODE=transparent|socks5`：默认 `transparent`，核心场景应始终覆盖该模式。
  - `TEST_INTERCEPT=iptables|ebpf|tun`：在 Linux 上校验实际拦截模式是否符合预期。
- 若目标是验证“应用本身不支持代理配置也能访问谷歌”，应优先使用 `bin/vproxy -v bin/test_google`，而不是给应用设置 `https_proxy`/`socks_proxy`。
