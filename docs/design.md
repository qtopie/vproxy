# vproxy Transparent Proxy Design

This document describes the robust transparent proxy architecture implemented in `vproxy` for Linux.

## Objective
Enable transparent TCP/UDP redirection for any application wrapped by `vproxy` (e.g., `vproxy agy`) without requiring the application to have built-in proxy support or environment variable configuration.

## Architecture

The system uses a hybrid approach combining **Cgroup v2**, **Iptables**, and **eBPF (SO_MARK)** to achieve high reliability and avoid common pitfalls like routing loops.

### 1. Process Isolation (Cgroup v2)
When `vproxy` starts a command:
- It creates a dedicated Cgroup at `/sys/fs/cgroup/vproxy`.
- It moves its own PID into this Cgroup.
- The target application (child process) inherits this Cgroup.
- This allows `iptables` to target traffic specifically from this process hierarchy.

### 2. Traffic Redirection (Iptables REDIRECT)
The system sets up specialized `nat` table rules:
- **Chain:** `VPROXY_REDIRECT` hooked into `OUTPUT`.
- **Match:** `iptables -m cgroup --path "vproxy"`.
- **Action:** `REDIRECT --to-ports 10080`.
- **Benefit:** Standard `iptables` redirection is extremely stable and allows for race-free destination lookup using `SO_ORIGINAL_DST`.

### 3. Loopback Bypass (eBPF & SO_MARK)
To prevent `vproxy` from intercepting its own connections to the upstream proxy:
- **Marker:** `vproxy` applies a socket mark `0xff` (bypass mark) to its outgoing upstream connections.
- **Implementation:** Uses a Go `net.Dialer.Control` function that performs `setsockopt(..., SO_MARK, 0xff)`.
- **Iptables Bypass:** A rule `-m mark --mark 0xff -j RETURN` is placed at the top of the chain.
- **Bypass eBPF:** An eBPF program can also be used to automatically apply these marks at the kernel level for all sockets created by the proxy.

### 4. Destination Resolution (TProxy)
The `proxy/tproxy` package handles incoming connections on port 10080:
- It uses the standard Linux `getsockopt(fd, IPPROTO_IP, SO_ORIGINAL_DST)` to retrieve the actual target IP and port.
- This method is synchronous and avoids the race conditions associated with shared eBPF maps and socket cookies.

## Modular Components

| Package | Responsibility |
| :--- | :--- |
| `proxy/tproxy` | Listening on port 10080 and resolving `SO_ORIGINAL_DST`. |
| `proxy/cgroup` | Managing `/sys/fs/cgroup/vproxy` and process migration. |
| `proxy/iptables` | Orchestrating `nat` rules for redirection and bypass. |
| `proxy/ebpf` | Capability checks and `SO_MARK` application logic. |

## Permission Handling
Since `iptables`, `cgroup` creation, and `SO_MARK` require elevated privileges (`CAP_NET_ADMIN`), `vproxy` includes a dynamic authorization flow:
1. It detects missing permissions at startup.
2. It prompts the user to run a one-time `sudo setcap` and directory setup.
3. It automatically restarts itself once permissions are granted.

## Traffic Flow Diagram
```text
[ Application (agy) ]
      |
      | (TCP Connect)
      v
[ Kernel Cgroup Match ] ---> [ Iptables REDIRECT ]
                                     |
                                     v
                             [ vproxy (10080) ]
                                     |
                                     | (Resolves Original DST)
                                     | (Applies SO_MARK 0xff)
                                     v
[ Kernel Mark Match ] <--- [ Iptables RETURN ]
      |
      | (Direct to Upstream)
      v
[ SOCKS5 Upstream ]
```
