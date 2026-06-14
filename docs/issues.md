## Issue: Verbose Mode (-v) Triggers Unintended TLS MITM (Resolved)

**Description:**
When starting the vproxy daemon or using the wrapper mode with the verbose flag (`-v`), HTTPS connections routed through the local HTTP proxy would hang with a `TLS handshake timeout`.

**Root Cause:**
Logging verbosity was coupled with MITM logic: `if IsVerbose() || action == ActionIntercept`. Standard clients didn't trust the ad-hoc Root CA.

**Resolution:**
Decoupled logging from logic. MITM now strictly requires an `INTERCEPT` rule.

---

## macOS Transparent Proxy Implementation: Architectural Evolution & Lessons Learned

### Phase 1: Global TUN Routing (Abandoned)
*   **Attempt:** Create a `utun` device, inject `0.0.0.0/1` and `128.0.0.0/1` routes, and use `IP_BOUND_IF` (socket option 25) to bypass the TUN for vproxy's outbound traffic.
*   **Result:** **Failure**. macOS routing priority is extremely aggressive. Even with `IP_BOUND_IF` and binding to a physical IP, outbound packets were often sucked back into the TUN, causing a loop or `Network is unreachable`.

### Phase 2: PF (Packet Filter) Architecture (Implemented)
*   **Attempt:** Use native PF firewall to redirect traffic.
    *   **Redirection:** `pass out on en0 route-to lo0 ...` to steer traffic to loopback.
    *   **Loop Prevention:** `user != root` filter to exempt the vproxy daemon.
*   **Findings:**
    *   **TLS Handshake Issues:** Initial rules only matched SYN packets. Data packets skipped the proxy, causing timeouts. Fixed by matching all packets in the flow.
    *   **Process Identification:** Running `lsof` per connection was too slow. Fixed by optimizing `lsof -i :port` for near-instant PID lookup.
    *   **Direct Network Stability (ICMP/Ping):** Even with `quick pass` rules, activating `route-to` on a physical interface causes PF state table conflicts for ICMP on many macOS versions. 
*   **Result:** **Stable for TCP/DNS**, but `ping` may be lost while `init` is active.

### Phase 3: Surgical PID-Based Routing (Winner)
*   **Attempt:** Introduce `RuleTypePID` and capture the child PID when running in wrapper mode (`bin/vproxy <cmd>`).
*   **Mechanism:** vproxy automatically prepends a high-priority `PID,XXXX,PROXY` rule for the child process at the start of the rule list.
*   **Result:** **100% Success**. This is the recommended way to use vproxy on macOS. It provides zero-side-effect, precise proxying without disturbing system-level networking or ICMP.

### Final Conclusion for macOS
Users should prefer the **Wrapper Mode** (`bin/vproxy cmd`) for daily development. The **Transparent Mode** (`vproxy init`) is available for global interception but carries the known kernel-level side effect of potentially breaking ICMP (ping) due to macOS PF's strict state handling.
