# vproxy

`vproxy` is a high-performance, lightweight, multi-platform transparent proxy server and wrapper tool written in Go. It enables transparent redirection of network traffic (TCP and UDP) for any application without requiring proxy environment variables, modification of application settings, or custom wrapper libraries. 

---

## 🚀 Key Features

* **Multi-Platform Support**: Seamless transparent proxying on **Linux**, **macOS**, and **Windows**.
* **Zero-Configuration Wrapping**: Run any target command via `vproxy run <command>` (e.g. `vproxy run curl https://google.com`) to intercept and proxy its traffic cleanly.
* **Hybrid Interception Architectures**:
  * **Linux**: High-performance kernel interception via Cgroup v2, Iptables (`REDIRECT`), and eBPF (`SO_MARK` bypass).
  * **macOS & Windows**: Virtual TUN interfaces (`utun` / `Wintun`) integrated with a `gvisor` userspace TCP/IP stack and OS routing tables.
* **Precision Process Path Matching**: Standard transparent proxies match rules using simple process command names. `vproxy` performs **full executable path matching** (e.g., matching rules to `/Applications/Telegram.app/Contents/MacOS/Telegram` on macOS or `C:\Program Files\Telegram Desktop\Telegram.exe` on Windows) dynamically, preventing name-spoofing attacks.
* **Advanced Rule System**: Filter and route traffic using rich, flexible rulesets supporting IP ranges, domains, full process paths, and action policies (e.g., `DIRECT` or `PROXY`).

---

## 🛠️ Architecture

`vproxy` is engineered to prevent routing loops and ensure absolute stability using native, high-performance platform tools:

```text
[ Target Application ]
          |
          | (TCP / UDP Connect)
          v
======================================================
  INTERCEPTION LAYER (Platform-Specific)
======================================================
  [Linux]                     [macOS / Windows]
  Cgroups v2                  Virtual TUN (utun/Wintun)
  + Iptables REDIRECT         + gvisor TCP/IP Stack
  + eBPF (SO_MARK)            + OS Routing Table Split
          \                          /
           \                        /
            v                      v
        ================================
        [      vproxy Local Server     ]
        ================================
          |
          | (Lookup destination & match rules)
          | (Apply outbound socket bypass tags)
          v
======================================================
  OUTBOUND & UPSTREAM BYPASS
======================================================
  [Linux]                     [macOS]             [Windows]
  SO_MARK 0xff                IP_BOUND_IF         IP_UNICAST_IF
          \                        |                   /
           \                       |                  /
            v                      v                 v
        ================================================
        [            Internet / Outbound Link          ]
        ================================================
```

### 1. Linux Interception (Cgroups & eBPF)
* Uses **Cgroup v2** to isolate the wrapped target process and all its children.
* Leverages **Iptables REDIRECT** on Cgroup matches to route traffic to the local `vproxy` port (`10080`).
* Applies **eBPF socket marking (`SO_MARK = 0xff`)** to downstream sockets created by `vproxy` itself, allowing outbound packets to bypass redirection and avoid routing loops.

### 2. macOS & Windows Interception (TUN & gvisor)
* Initializes a virtual TUN device (`utun` on macOS, `Wintun` on Windows).
* Attaches a **gvisor userspace TCP/IP stack** to the TUN endpoint to handle IP packets efficiently without elevated kernel-level privileges.
* Modifies OS routing tables to route traffic via split subnets (`0.0.0.0/1` and `128.0.0.0/1`) through the TUN interface.
* Implements direct system calls (`IP_BOUND_IF` on macOS, `IP_UNICAST_IF` on Windows via `ws2_32.dll`) to bind `vproxy`'s outbound sockets directly to the physical interface, bypassing the virtual TUN and preventing routing loops.

---

## ⚙️ Configuration & Rules

`vproxy` is configured via a JSON file. By default, it searches for a configuration file in the following order:
1. Manually specified file (via `-c` flag).
2. System-wide global config: `/etc/vproxy/config.json` (on Linux) or `~/.vproxy/config.json` (on macOS/Windows).
3. Local file in the current directory: `vproxy.json`.

### Configuration Example (`/etc/vproxy/config.json` or `vproxy.json`)
```json
{
  "upstreams": [
    "socks5://127.0.0.1:1080"
  ],
  "rules": [
    "PROCESS,/Applications/Telegram.app/Contents/MacOS/Telegram,DIRECT",
    "PROCESS,C:\\Program Files\\Telegram Desktop\\Telegram.exe,DIRECT",
    "DOMAIN-SUFFIX,google.com,PROXY",
    "IP-CIDR,192.168.0.0/16,DIRECT",
    "FINAL,PROXY"
  ]
}
```

### Rule Syntax
Rules are parsed and matched top-down:
* **PROCESS**: Match full process executable path (contains matching, e.g. `PROCESS,Telegram,DIRECT`).
* **DOMAIN-SUFFIX**: Match hosts ending in specific domain.
* **IP-CIDR**: Match target IP ranges.
* **FINAL**: Default fallback action (`PROXY` or `DIRECT`).

---

## 🔨 Building from Source

### Prerequisites
* Go 1.21 or newer installed.
* **Windows**: Requires the `wintun.dll` driver installed or placed in the working directory (download from [wintun.net](https://www.wintun.net/)).
* **macOS / Linux**: Administrator (sudo) privileges required for raw socket bind/interface modifications.

### Compilation
Build the binary for your local platform:
```bash
go build -o bin/vproxy ./cmd/vproxy
```

Cross-compile for other platforms:
```bash
# macOS (Intel & Apple Silicon)
GOOS=darwin GOARCH=amd64 go build -o bin/vproxy-darwin-amd64 ./cmd/vproxy
GOOS=darwin GOARCH=arm64 go build -o bin/vproxy-darwin-arm64 ./cmd/vproxy

# Windows (64-bit)
GOOS=windows GOARCH=amd64 go build -o bin/vproxy-windows.exe ./cmd/vproxy

# Linux (64-bit)
GOOS=linux GOARCH=amd64 go build -o bin/vproxy-linux ./cmd/vproxy
```

---

## 💻 Usage

### 1. Initialize Background Service (TUN/System-Wide Mode)
Starts the transparent proxy routing engine globally.
```bash
sudo vproxy init
```

### 2. Wrap Individual Commands (Cgroups-isolated CLI Wrapping)
Run a specific application through `vproxy`'s transparent proxy pipeline:
```bash
# Under Linux (requires CAP_NET_ADMIN privileges, prompts auto-setup on launch)
vproxy curl -v https://google.com
```

### 3. Clear and Tear Down Routing Rules
Restore the original system routing tables and dismantle the virtual TUN interfaces:
```bash
sudo vproxy clean
```

---

## 📄 License
This project is licensed under the MIT License.
