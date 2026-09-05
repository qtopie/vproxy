package internal

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/qtopie/vproxy/internal/ipc"
	"github.com/qtopie/vproxy/internal/mitm"
	"github.com/qtopie/vproxy/proxy/cgroup"
	"github.com/qtopie/vproxy/proxy/ebpf"
	"github.com/qtopie/vproxy/proxy/iptables"
	"github.com/qtopie/vproxy/proxy/tproxy"
)

type App struct {
	Config     *Config
	ConfigPath string
	LocalSocks int
	LocalHTTP  int
	LocalTrans int

	ebpfResult *ebpf.LoadResult // Strong reference to prevent GC of eBPF FDs
	ipcServer  *ipc.Server
	ph         *ProxyHandler
}

func (a *App) getProxyHandler() *ProxyHandler {
	return a.ph
}

// RequestStatus delegates to the IPC client to query the background daemon's status.
func RequestStatus() (*ipc.StatusResponse, error) {
	return ipc.RequestStatus()
}

// SelfHeal re-verifies and restores the system-wide transparent proxying environment.
func (a *App) SelfHeal() error {
	if runtime.GOOS != "linux" || os.Getenv("VP_USE_TUN") == "1" || a.Config.EnableEbpf == nil || !*a.Config.EnableEbpf {
		return nil
	}

	Infof("Auditing/Repairing system-wide transparent proxying rules...")

	// 1. Check Permissions
	if err := ebpf.CheckPermission(); err != nil {
		return fmt.Errorf("permission check failed: %v", err)
	}

	// 2. Ensure Cgroup
	if err := cgroup.EnsureVProxyCgroup(); err != nil {
		return fmt.Errorf("cgroup setup failed: %v", err)
	}

	// 3. Determine setup parameters
	isUpstreamTProxyAlive := false
	var bestURL *url.URL
	best := a.getBestUpstream()
	if best != "" {
		bestURL, _ = url.Parse(best)
		if bestURL != nil && bestURL.Scheme == "tproxy" {
			isUpstreamTProxyAlive = true
		}
	}

	setupTarget := fmt.Sprintf("%d", a.ph.TransPort)
	if isUpstreamTProxyAlive {
		setupTarget = bestURL.Host
	}

	isRemoteTProxy := false
	var upstreamIP net.IP
	var upstreamPort uint16
	if isUpstreamTProxyAlive {
		isRemoteTProxy = true
		host, portStr, err := net.SplitHostPort(bestURL.Host)
		if err == nil {
			upstreamIP = net.ParseIP(host)
			var p int
			fmt.Sscanf(portStr, "%d", &p)
			upstreamPort = uint16(p)
		}
	}

	// 4. Setup Redirection
	const cgroupPath = "/sys/fs/cgroup/vproxy"
	if ebpf.IsKernelSupported() && os.Getenv("VP_FORCE_IPTABLES") != "1" {
		r, err := ebpf.Load(cgroupPath, uint16(a.ph.TransPort), 0xff, isRemoteTProxy, upstreamIP, upstreamPort)
		if err == nil {
			if a.ebpfResult != nil {
				a.ebpfResult.Unload()
			}
			a.ebpfResult = r
			a.ph.SetEbpfResult(r)
			Infof("eBPF redirect active (system-wide)")
			ebpf.SetEnabled(true)
			SetDialerControl(ebpf.GetDialerControl())
			return nil
		} else {
			Errorf("eBPF load failed: %v, falling back to iptables", err)
		}
	}

	// iptables fallback
	if err := iptables.SetupRules(setupTarget, isRemoteTProxy, upstreamIP, upstreamPort); err != nil {
		return fmt.Errorf("iptables setup failed: %v", err)
	}

	Infof("iptables redirect active (system-wide)")
	ebpf.SetEnabled(true)
	SetDialerControl(ebpf.GetDialerControl())
	return nil
}

func (a *App) getBestUpstream() string {
	if a.ph != nil && a.ph.sm != nil {
		return a.ph.sm.GetBestServer()
	}
	return ""
}

func (a *App) RunServer() {
	sm, ph := a.setupServices()
	a.ph = ph
	sm.Start()

	// 1. Setup Management Web UI
	mtf := NewMemoryTraceFormatter(100)
	RegisterFormatter(mtf)
	StartWebServer(a, mtf)

	if err := ph.StartSocks(); err != nil {
		msg := fmt.Sprintf("Failed to start SOCKS5 proxy: %v", err)
		Fatal(msg)
	}
	if err := ph.StartHTTP(); err != nil {
		msg := fmt.Sprintf("Failed to start HTTP proxy: %v", err)
		Fatal(msg)
	}

	// Start IPC Server for unprivileged wrappers to request cgroup migration
	if srv, err := ipc.StartServer(a.SelfHeal); err == nil {
		a.ipcServer = srv
		Infof("IPC server started on %s", ipc.SocketPath)
	} else {
		Errorf("Failed to start IPC server: %v", err)
	}

	best := sm.GetBestServer()
	isUpstreamTProxyAlive := false
	var bestURL *url.URL
	if best != "" {
		bestURL, _ = url.Parse(best)
		if bestURL != nil && bestURL.Scheme == "tproxy" {
			isUpstreamTProxyAlive = true
		}
	}

	if !isUpstreamTProxyAlive {
		if err := ph.StartTransparent(); err != nil {
			msg := fmt.Sprintf("Failed to start transparent proxy: %v", err)
			Fatal(msg)
		}
	} else {
		Debugf("Upstream provides tproxy directly and is ALIVE: %s, not starting local transparent proxy in server mode", best)
	}

	// On Linux, if transparent proxy is enabled, we need to setup the global redirection rules
	if err := a.SelfHeal(); err != nil {
		Fatalf("Initialization failed: %v. Please run 'sudo vproxy init' to set up capabilities.", err)
	}
	if runtime.GOOS == "windows" {
		if readyFile := os.Getenv("VP_READY_FILE"); readyFile != "" {
			if err := os.WriteFile(readyFile, []byte("ready\n"), 0600); err != nil {
				Fatalf("failed to signal startup readiness: %v", err)
			}
		}
	}

	a.printVerboseStatus(ph, sm, a.ebpfResult != nil, isUpstreamTProxyAlive, best)

	a.PrintConnectivityOK()

	go a.watchConfig(a.ConfigPath, ph)
	go a.monitorNetwork(sm)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	Debugf("Shutting down...")
	if a.ebpfResult != nil {
		a.ebpfResult.Unload()
	} else if a.Config.EnableEbpf != nil && *a.Config.EnableEbpf && runtime.GOOS == "linux" {
		iptables.CleanupRules()
	}

	if a.ipcServer != nil {
		a.ipcServer.Stop()
	}

	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		tproxy.Cleanup()
	}
	ph.Stop()
	sm.Stop()
}

func (a *App) RunWrapper(args []string) {
	cmdName := args[0]
	cmdArgs := args[1:]
	Debugf("running command %v", args)

	baseName := filepath.Base(cmdName)
	isTUN := os.Getenv("VP_USE_TUN") == "1"
	needsEbpf := true
	needsTransparent := true
	needsBridges := true
	if isTUN {
		needsEbpf = false
	} else {
		switch baseName {
		case "curl", "git", "code", "gemini", "test_ebpf", "test_tproxy":
			// Tools in this list should NOT be intercepted by eBPF/iptables.
			// They are either proxy-aware (via env vars) or part of the test suite.
			// 'gemini' uses standard HTTP_PROXY/HTTPS_PROXY.
			needsEbpf = false
			needsTransparent = false
			needsBridges = true
		case "agy":
			// 'agy' MUST use transparent proxy (cgroup redirection) to work correctly on Linux.
			// Do not add to the whitelist above.
			needsEbpf = true
			needsTransparent = true
			needsBridges = false
		}
	}

	// Check early if a background daemon is running (pidFile exists).
	// Use a fixed path so it matches regardless of whether the daemon was
	// started with sudo.
	pidFile := GetPIDFilePath()
	skipPrivileged := false
	if _, err := os.Stat(pidFile); err == nil {
		skipPrivileged = true
		Debugf("Background vproxy detected (PID file: %s)", pidFile)
	}

	// Fast-path: when the background daemon is already running AND this tool is
	// proxy-aware (uses HTTP_PROXY env vars), skip all service setup and use the
	// daemon's existing local HTTP port directly. This avoids both the synchronous
	// upstream probe (~5s) and bridge startup conflicts with the daemon's bindings.
	if skipPrivileged && !needsEbpf && needsBridges && !isTUN {
		directHTTPProxy := fmt.Sprintf("http://127.0.0.1:%d", a.LocalHTTP)
		Debugf("Fast-path: background daemon detected, using existing HTTP bridge at %s", directHTTPProxy)
		env := os.Environ()
		env = append(env, fmt.Sprintf("http_proxy=%s", directHTTPProxy))
		env = append(env, fmt.Sprintf("https_proxy=%s", directHTTPProxy))
		env = append(env, fmt.Sprintf("HTTP_PROXY=%s", directHTTPProxy))
		env = append(env, fmt.Sprintf("HTTPS_PROXY=%s", directHTTPProxy))
		env = a.appendNoProxyEnv(env)
		cmd := exec.Command(cmdName, cmdArgs...)
		cmd.Env = env
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Start(); err != nil {
			Fatalf("Command execution failed: %v", err)
		}

		// Dynamic PID rule injection for surgical proxying
		Debugf("Dynamic PID rule injected for %d (PROXY)", cmd.Process.Pid)

		if err := cmd.Wait(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			Fatalf("Command execution failed: %v", err)
		}
		return
	}

	sm, ph := a.setupServices()
	sm.Start()

	// Simplified upstream selection
	best := sm.GetBestServer()
	isUpstreamTProxyAlive := false
	if best != "" {
		if u, err := url.Parse(best); err == nil && u.Scheme == "tproxy" {
			isUpstreamTProxyAlive = true
		}
	}

	if best == "" {
		servers := sm.GetServers()
		if len(servers) > 0 {
			best = servers[0]
			Errorf("No verified upstream available, defaulting to first: %s", best)
		} else {
			Fatal("No upstream servers configured")
		}
	} else {
		Debugf("Using verified upstream: %s", best)
	}

	bestURL, _ := url.Parse(best)

	var ebpfResult *ebpf.LoadResult
	cleanup := func() {
		if ebpfResult != nil {
			ebpfResult.Unload()
			ebpfResult = nil
		} else if needsEbpf && runtime.GOOS == "linux" {
			// iptables fallback: clean up rules on exit.
			iptables.CleanupRules()
		}
		if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
			tproxy.Cleanup()
		}
		ph.Stop()
		sm.Stop()
	}
	defer cleanup()

	// 1. Setup Transparent Proxying Components
	// (skipPrivileged and pidFile already computed above for the fast-path check)
	Debugf("Checking for background daemon at %s", pidFile)
	if _, err := os.Stat(pidFile); err == nil {
		// Re-confirm skipPrivileged for the transparent-proxy path below.
		skipPrivileged = true
		Debugf("Background vproxy detected, skipping privileged server setup")
	}

	// Always attempt cgroup migration on Linux if transparent proxying is REQUESTED for this command
	// Note: 'agy' requires this migration even if a background server is already handling rules.
	if needsEbpf && a.Config.EnableEbpf != nil && *a.Config.EnableEbpf && runtime.GOOS == "linux" {
		if err := cgroup.MoveProcessToVProxyCgroup(os.Getpid()); err != nil {
			Debugf("Direct cgroup migration failed (%v), trying IPC attach...", err)
			if ipcErr := ipc.RequestAttach(os.Getpid()); ipcErr != nil {
				Debugf("IPC attach failed: %v", ipcErr)

				// TRIGGER SELF-HEAL: If IPC attach fails, the environment might be tampered.
				// Request the daemon to repair itself.
				if skipPrivileged {
					Infof("Environment seems tampered, requesting daemon to self-heal...")
					if repairErr := ipc.RequestRepair(); repairErr == nil {
						// Retry attach once after repair
						ipcErr = ipc.RequestAttach(os.Getpid())
					}
				}

				if ipcErr != nil {
					if !skipPrivileged && needsEbpf {
						msg := "vproxy process migration failed! Please initialize the environment by running: 'sudo vproxy init'"
						Fatal(msg)
					} else {
						// If we failed to move to cgroup, it's not always fatal if skipPrivileged is true (maybe already there)
						// but for tests it might be an issue.
						msg := fmt.Sprintf("WARNING: Failed to move %s to vproxy cgroup via direct write or IPC: %v. Transparent proxying might NOT work.", cmdName, ipcErr)
						Debugf(msg)
					}
				}
			} else {
				Debugf("Successfully moved process %d (%s) to vproxy cgroup via IPC", os.Getpid(), cmdName)
			}
		} else {
			Debugf("Successfully moved process %d (%s) to vproxy cgroup via direct write", os.Getpid(), cmdName)
		}

		// If we're on Linux, we also need to ensure SO_MARK is set for our own bridges
		ebpf.SetEnabled(true)
		SetDialerControl(ebpf.GetDialerControl())
	}

	if (needsEbpf || skipPrivileged) && (isTUN || (a.Config.EnableEbpf != nil && *a.Config.EnableEbpf)) && runtime.GOOS == "linux" && needsTransparent {
		// Check if we have permissions to set SO_MARK (requires CAP_NET_ADMIN)
		if !skipPrivileged {
			if err := ebpf.CheckPermission(); err != nil && !isTUN {
				msg := "vproxy permission check failed! Please initialize the environment by running: 'sudo vproxy init'"
				Fatal(msg)
			}

			// Ensure cgroup exists (already moved to it above, but ensure directory exists)
			if err := cgroup.EnsureVProxyCgroup(); err != nil && !isTUN {
				msg := "vproxy permission check failed! Please initialize the environment by running: 'sudo vproxy init'"
				Fatal(msg)
			}
		}

		// Attempt eBPF-native redirect (kernel >= 5.7).
		// On failure, fall back to iptables automatically.
		var setupTarget string
		if isUpstreamTProxyAlive {
			setupTarget = bestURL.Host
		} else {
			if !skipPrivileged {
				if err := ph.StartTransparent(); err != nil {
					msg := fmt.Sprintf("Failed to start transparent bridge: %v", err)
					Errorf(msg)
				}
				setupTarget = fmt.Sprintf("%d", ph.TransPort)
			} else {
				// If background server is running, we don't need to start a local bridge
				// or setup iptables rules here. The background server handles it.
				Debugf("Background vproxy handles transparent proxying, skipping local bridge/iptables setup")
				needsEbpf = false
			}
		}

		if needsEbpf {
			const cgroupPath = "/sys/fs/cgroup/vproxy"
			proxyPort := uint16(ph.TransPort)
			const bypassMark = uint32(0xff)

			isRemoteTProxy := false
			var upstreamIP net.IP
			var upstreamPort uint16

			if isRemoteTProxy {
				if host, portStr, err := net.SplitHostPort(setupTarget); err == nil {
					upstreamIP = net.ParseIP(host)
					var p int
					if _, err := fmt.Sscanf(portStr, "%d", &p); err == nil {
						upstreamPort = uint16(p)
					}
				}
			}

			if ebpf.IsKernelSupported() && os.Getenv("VP_FORCE_IPTABLES") != "1" {
				r, err := ebpf.Load(cgroupPath, proxyPort, bypassMark, isRemoteTProxy, upstreamIP, upstreamPort)
				if err != nil {
					Debugf("eBPF load failed (%v), falling back to iptables", err)
				} else {
					ebpfResult = r
					ph.SetEbpfResult(r)
					Debugf("eBPF redirect active (wrapper mode)")
				}
			}

			if ebpfResult == nil {
				// iptables fallback.
				if err := iptables.SetupRules(setupTarget, isRemoteTProxy, upstreamIP, upstreamPort); err != nil {
					msg := fmt.Sprintf("Fatal: iptables setup failed: %v", err)
					Fatal(msg)
				}
				Debugf("iptables redirect active (IPv4 TCP+UDP only)")
			}

			// Ensure cleanup on unexpected signals
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigCh
				cleanup()
				os.Exit(1)
			}()
		}
	}

	a.printVerboseStatus(ph, sm, ebpfResult != nil, isUpstreamTProxyAlive, best)

	env := os.Environ()
	if IsVerbose() {
		if err := mitm.EnsureCA(); err == nil {
			caPath := mitm.GetCACertPath()
			env = append(env, fmt.Sprintf("SSL_CERT_FILE=%s", caPath))
			// Node.js specific CA support
			env = append(env, fmt.Sprintf("NODE_EXTRA_CA_CERTS=%s", caPath))
			Debugf("Tracing CA injected into environment: SSL_CERT_FILE=%s, NODE_EXTRA_CA_CERTS=%s", caPath, caPath)
		} else {
			Errorf("Failed to initialize dynamic CA: %v", err)
		}
	}

	// If background vproxy is running and this tool needs transparent proxying,
	// we don't need to set environment variables or start bridges because TUN/iptables/eBPF will intercept it.
	// For tools that use env-vars (needsEbpf=false), we always proceed to set them.
	if (skipPrivileged || needsTransparent) && needsEbpf {
		Debugf("Transparent proxying active (skipPrivileged=%v), executing %s directly", skipPrivileged, cmdName)
		cmd := exec.Command(cmdName, cmdArgs...)
		cmd.Env = env
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin

		err := cmd.Run()
		cleanup()

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			Fatalf("Command execution failed: %v", err)
		}
		return
	}

	var finalHTTPProxy string
	var finalSocksProxy string

	var isHTTPTool bool
	baseName = filepath.Base(cmdName)
	switch baseName {
	case "curl", "git", "gemini":
		// 'agy' is excluded here to ensure it doesn't get HTTP_PROXY env vars
		// that might conflict with its transparent proxying requirement.
		isHTTPTool = true
	default:
		isHTTPTool = false
	}

	// Determine HTTP proxy requirement
	if needsBridges {
		if bestURL.Scheme == "http" {
			finalHTTPProxy = best
			Debugf("Protocol match: using upstream HTTP proxy directly for %s", cmdName)
		} else {
			if err := ph.StartHTTP(); err != nil {
				msg := fmt.Sprintf("Failed to start local HTTP bridge: %v", err)
				Fatal(msg)
			}
			finalHTTPProxy = fmt.Sprintf("http://127.0.0.1:%d", ph.HttpPort)
			Debugf("Protocol mismatch (upstream is %s): started local HTTP bridge at %s", bestURL.Scheme, finalHTTPProxy)
		}

		// Determine SOCKS5 proxy requirement (only if not a specific HTTP tool)
		if !isHTTPTool {
			if bestURL.Scheme == "socks5" {
				finalSocksProxy = best
				Debugf("Protocol match: using upstream SOCKS5 proxy directly")
			} else {
				if err := ph.StartSocks(); err != nil {
					msg := fmt.Sprintf("Failed to start local SOCKS5 bridge: %v", err)
					Fatal(msg)
				}
				finalSocksProxy = fmt.Sprintf("socks5://127.0.0.1:%d", ph.SocksPort)
				Debugf("Protocol mismatch (upstream is %s): started local SOCKS5 bridge at %s", bestURL.Scheme, finalSocksProxy)
			}
		}
	}

	var newArgs []string
	switch baseName {
	case "curl":
		newArgs = append([]string{"-x", finalHTTPProxy}, cmdArgs...)
	case "code":
		// VS Code uses --proxy-server argument
		newArgs = append([]string{fmt.Sprintf("--proxy-server=%s", finalHTTPProxy)}, cmdArgs...)
	case "git", "gemini":
		// 'agy' uses transparent proxy, so it doesn't need HTTP_PROXY env vars.
		env = append(env, fmt.Sprintf("http_proxy=%s", finalHTTPProxy))
		env = append(env, fmt.Sprintf("https_proxy=%s", finalHTTPProxy))
		env = append(env, fmt.Sprintf("HTTP_PROXY=%s", finalHTTPProxy))
		env = append(env, fmt.Sprintf("HTTPS_PROXY=%s", finalHTTPProxy))
		env = a.appendNoProxyEnv(env)
		newArgs = cmdArgs
	default:
		if !needsEbpf {
			env = append(env, fmt.Sprintf("http_proxy=%s", finalHTTPProxy))
			env = append(env, fmt.Sprintf("https_proxy=%s", finalHTTPProxy))
			env = append(env, fmt.Sprintf("all_proxy=%s", finalSocksProxy))
			env = append(env, fmt.Sprintf("HTTP_PROXY=%s", finalHTTPProxy))
			env = append(env, fmt.Sprintf("HTTPS_PROXY=%s", finalHTTPProxy))
			env = append(env, fmt.Sprintf("ALL_PROXY=%s", finalSocksProxy))
			env = a.appendNoProxyEnv(env)
		}
		newArgs = cmdArgs
	}

	Debugf("Executing command: %s %v", cmdName, newArgs)
	// Only print connectivity OK if we actually have a working server
	if sm.HasWorkingServer() {
		a.PrintConnectivityOK()
	}

	cmd := exec.Command(cmdName, newArgs...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err := cmd.Run()
	cleanup()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		Fatalf("Command execution failed: %v", err)
	}
}

func (a *App) PrintConnectivityOK() {
	ok := "OK"
	if a.checkColorSupport() {
		ok = "\033[32mOK\033[0m"
	}
	Infof("vproxy connectivity: %s", ok)
}

func (a *App) checkColorSupport() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	term := os.Getenv("TERM")
	if term == "dumb" {
		return false
	}
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

func (a *App) appendNoProxyEnv(env []string) []string {
	noProxy := "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16"
	return append(env, fmt.Sprintf("no_proxy=%s", noProxy), fmt.Sprintf("NO_PROXY=%s", noProxy))
}

func (a *App) setupServices() (*ServerManager, *ProxyHandler) {
	sm := NewServerManager(a.Config.Upstreams, time.Duration(a.Config.TestInterval)*time.Second, 5*time.Second)
	if sm == nil {
		Fatal("No upstream servers configured")
	}

	rm := NewRuleManager(a.Config.Rules)
	if a.Config.DirectDNS != nil {
		rm.SetDirectDNS(*a.Config.DirectDNS)
	}
	ph := NewProxyHandler(sm, rm, a.LocalSocks, a.LocalHTTP, a.LocalTrans, a.Config.WebPort)
	if len(a.Config.BypassNodes) > 0 {
		ph.SetBypassNodes(a.Config.BypassNodes)
	}
	if a.Config.DialTimeoutMs != nil {
		ph.DialTimeout = time.Duration(*a.Config.DialTimeoutMs) * time.Millisecond
	}
	if a.Config.DialRetryCount != nil {
		ph.DialRetryCount = *a.Config.DialRetryCount
	}
	return sm, ph
}

func (a *App) watchConfig(path string, ph *ProxyHandler) {
	stat, err := os.Stat(path)
	if err != nil {
		return
	}
	lastMod := stat.ModTime()
	for {
		time.Sleep(1 * time.Second)
		stat, err := os.Stat(path)
		if err != nil {
			continue
		}
		if stat.ModTime().After(lastMod) {
			lastMod = stat.ModTime()
			cfg, _, err := LoadConfig(path)
			if err == nil {
				ph.UpdateServers(cfg.Upstreams)
				directDNS := true
				if cfg.DirectDNS != nil {
					directDNS = *cfg.DirectDNS
				}
				ph.UpdateRules(cfg.Rules, directDNS)
				ph.SetBypassNodes(cfg.BypassNodes)
				Debugf("Config reloaded")
			}
		}
	}
}

func (a *App) monitorNetwork(sm *ServerManager) {
	wasOffline := false
	healTicker := time.NewTicker(15 * time.Minute)
	defer healTicker.Stop()

	for {
		select {
		case <-healTicker.C:
			if err := a.SelfHeal(); err != nil {
				Errorf("Periodic SelfHeal failed: %v", err)
			}
		case <-time.After(15 * time.Second):
			d := net.Dialer{
				Timeout: 3 * time.Second,
				Control: GetDialerControl(),
			}
			conn, err := d.Dial("tcp", "8.8.8.8:53")
			if err != nil {
				wasOffline = true
				continue
			}
			conn.Close()
			if wasOffline {
				wasOffline = false
				servers := sm.GetServers()
				if len(servers) > 1 {
					sm.UpdateServers(servers)
				}
			}
		}
	}
}

func (a *App) printVerboseStatus(ph *ProxyHandler, sm *ServerManager, isEbpfActive bool, isUpstreamTProxy bool, upstream string) {
	if !IsVerbose() {
		return
	}

	// 1. IPv6 availability check
	ipv6Available := "Unavailable"
	ln6, err := net.Listen("tcp6", "[::1]:0")
	if err == nil {
		ipv6Available = "Available (Loopback Active)"
		ln6.Close()
	}

	// 2. eBPF maps status
	ebpfStatus := "Inactive"
	if isEbpfActive {
		ebpfStatus = "Active (Maps Loaded: tcp_orig_dst, udp_orig_dst, cidr_bypass_map)"
	} else if _, err := os.Stat("/tmp/vproxy.pid"); err == nil {
		if a.Config.EnableEbpf != nil && *a.Config.EnableEbpf {
			ebpfStatus = "Active (Delegated to system-wide background vproxy server)"
		} else {
			ebpfStatus = "Inactive (Delegated to background server, but eBPF is disabled in config)"
		}
	}

	// 3. iptables info
	iptablesInfo := "Inactive"
	if !isEbpfActive && runtime.GOOS == "linux" && os.Getenv("VP_USE_TUN") != "1" {
		if _, err := os.Stat("/tmp/vproxy.pid"); err == nil {
			if a.Config.EnableEbpf != nil && !*a.Config.EnableEbpf {
				iptablesInfo = "Active (Delegated to system-wide background vproxy server)"
			} else {
				iptablesInfo = "Inactive (Using eBPF system-wide instead)"
			}
		} else {
			iptablesInfo = "Active fallback (TPROXY redirection configured)"
		}
	}

	// 3b. TUN interface status
	tunStatus := "Inactive"
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" || (runtime.GOOS == "linux" && os.Getenv("VP_USE_TUN") == "1") {
		tunStatus = "Active (TUN interface redirection configured)"
	}

	// 4. Upstream Connection Info
	upstreamInfo := "None configured"
	if upstream != "" {
		upstreamInfo = fmt.Sprintf("Active upstream: %s (Verified)", upstream)
	}

	Debugf("=================== vproxy System Status ===================")
	Debugf("[STATUS] IPv6 Availability:     %s", ipv6Available)
	Debugf("[STATUS] eBPF Redirect Status:   %s", ebpfStatus)
	Debugf("[STATUS] iptables Redirection:   %s", iptablesInfo)
	Debugf("[STATUS] TUN Interface Status:   %s", tunStatus)
	Debugf("[STATUS] Upstream Proxy:        %s", upstreamInfo)
	Debugf("[STATUS] Local SOCKS5 Port:      %d", a.LocalSocks)
	Debugf("[STATUS] Local HTTP Port:        %d", a.LocalHTTP)
	Debugf("[STATUS] Local Transparent Port: %d", ph.TransPort)
	Debugf("============================================================")
}
