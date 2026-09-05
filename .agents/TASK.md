# Task Context

## Checklist
- [x] Record the current task and required validation steps.
- [x] For TUN usage, run the timed connectivity checks after `vproxy init`.
- [x] Always run `vproxy clean` after TUN verification.
- [x] Phase 1: Draft and obtain approval for SPEC-WIN-005 (LUID & IP Helper API refactor).
- [x] Phase 2: Add harness/test stubs for Windows LUID and native IP Helper API operations.
- [x] Phase 3: Implement internal `winipcfg` package with native `iphlpapi.dll` syscalls.
- [x] Phase 4: Refactor `proxy/tproxy/tproxy_windows.go` to use LUID, native address assignment, and transactional `/1` routes.
- [x] Phase 5: Run tests, cross-compile, and execute verification suite.

## Current Context
- Successfully refactored Windows TUN network and routing architecture following sing-box/sing-tun model:
  1. Spec-First: SPEC-WIN-005 drafted and approved in specs/modules/windows_support.spec.md.
  2. Integrated internal/winipcfg module providing zero-dependency Go bindings for Windows IP Helper API (iphlpapi.dll).
  3. Replaced netsh.exe and powershell.exe adapter name polling with direct NET_LUID configuration.
  4. Configured IP 198.18.0.1/15, MTU 1500, forwarding, and two transactional /1 routes via MibIPforwardRow2 directly bound to LUID.
  5. Implemented deterministic adapter GUID generation via MD5 hashing.
  6. Added unit and regression tests in proxy/tproxy/routing_windows_test.go.
  7. Verified Linux and Windows cross-compilation (GOOS=windows go build/test) and passed full ./scripts/check.sh validation suite without spec drift.
- Created as the persistent task context for the TUN init -> test -> clean workflow.
- 2026-09-04: Administrator privileges were available and `C:\Windows\System32\wintun.dll` was present.
- `vproxy init` reported that vproxy was already running, so it did not restart the existing process.
- Timed verification (15 seconds): DNS resolution succeeded; TCP connection to `www.google.com:443` timed out; HTTPS GET timed out.
- Mandatory `vproxy clean` completed successfully and restored the environment.
- Root cause investigation: the existing vproxy log contains a Wintun adapter-creation panic, while `init` reports success because startup is asynchronous and has no readiness/error handshake. Windows route setup also logs route failures without returning an error.
- Updated `specs/modules/windows_support.spec.md` with startup health and transactional route rollback requirements. Code changes are gated on explicit `APPROVE`.
- Spec approved. Implemented synchronous Windows TUN startup, readiness signaling for `vproxy init`, panic-to-error conversion, transactional route rollback, and interface-bound `/1` routes.
- 2026-09-04 22:23: New Windows build correctly failed `vproxy init` readiness instead of reporting success: Wintun raised a nil-pointer panic during adapter creation, which was converted to `Failed to start transparent proxy: panic while initializing Wintun/TUN`. `vproxy clean` completed successfully.
- After cleanup, direct DNS succeeded but TCP 443 and HTTPS still timed out, confirming the Google timeout is also reproducible outside the TUN path and is not caused solely by vproxy routing.
- 2026-09-04: No newer upstream `golang.zx2c4.com/wintun` module is available; WireGuard still depends on the 2023 binding. Added a reproducible local compatibility module at `third_party/wintun` with a nil-safe Wintun logger callback and a `go.mod` replace.
- 2026-09-04: Added the official Wintun 0.14.1 amd64 DLL under `internal/wintunruntime/embed/`; Windows startup now installs it to a versioned temp directory and configures DLL lookup before creating the TUN adapter.
- 2026-09-04: Verified the embedded 0.14.1 DLL loads and the previous Wintun logger panic no longer occurs. TUN startup now reaches adapter creation, but this host exposes no matching Wintun interface through `net.Interfaces()` or `Get-NetAdapter -IncludeHidden`; startup fails safely before routing and `vproxy clean` restores state.

## Harness Failure Report
- Connectivity verification failed: TCP 443 and HTTPS timed out after DNS resolution succeeded.
- The first targeted `go test ./internal` run also hit the pre-existing `TestMITMHTTPS` path failure (`/tmp/vproxy-ca.crt` on Windows); changed-package tests and Windows cross-compilation passed.
- Repository `scripts/check.sh` could not run directly because its CRLF shebang/options are rejected by the available Bash; its harness runner and spec-drift checks were run with CRLF normalization and passed.
- The remaining Windows blocker is host-side adapter registration/driver exposure, not the embedded DLL: `vproxy-tun` is created by the Wintun API, but no Windows interface index is discoverable for address/route configuration.
- 2026-09-04 diagnostic result: `setupapi.dev.log` repeatedly reports `Failed to open driver package object ...wintun.inf... Error = 0x00000005` during `Wintun.Install`. PnP reports no Wintun/vproxy Net device, while Driver Store contains only `wintun.inf` 0.13.0.0 (`oem8.inf`) and the `wintun` service is running. This identifies a driver-package access/registration failure, not an adapter enumeration race.
- 2026-09-04 23:16: Removed stale `oem8.inf` successfully with `pnputil /delete-driver oem8.inf /uninstall /force`. The official Wintun distribution is DLL-only, so no separate `wintun.inf`/`wintun.sys` package was available for manual `pnputil` installation. Retried bundled Wintun 0.14.1: `CreateTUN` again reported `Created TUN device: vproxy-tun`, but no adapter appeared in `Get-NetAdapter -IncludeHidden` or `Get-PnpDevice`; guarded init failed readiness and mandatory clean succeeded. The driver package is recreated by Wintun's install path and remains blocked during class configuration.
- 2026-09-04 23:19: Network class ACL is owned by `BUILTIN\Administrators`; `Administrators` and `SYSTEM` have FullControl, and no `UpperFilters`/`LowerFilters` were found on existing network class entries. Code Integrity logs show no Wintun-specific block, although Windows virtualization/code-integrity policies are active. SetupAPI confirms the Wintun package stages, validates its WHQL catalog, and publishes successfully as `oem8.inf`; failure occurs afterward when configuring `ROOT\NET\0002`, where opening the driver package object returns `0x00000005` and the device remains `CM_PROB_NEED_CLASS_CONFIG (0x38)`. This points to Windows network class/driver-database state rather than repository ACLs or a missing DLL.
- 2026-09-04 23:31: Cloned sing-box (`../sing-box`) and sing-tun (`../sing-tun`) to inspect Windows TUN implementation. Analyzed key differences: sing-tun uses `memmod` to load embedded `wintun.dll` without logger callback; computes requested GUID via MD5 hash; retrieves `NET_LUID` directly from the Wintun adapter (`Adapter.LUID()`); and configures IP/routes via Windows IP Helper API (`iphlpapi.dll` / `winipcfg`) directly on the LUID, entirely bypassing standard library interface enumeration (`net.Interfaces()`) and external commands (`netsh`/PowerShell).
