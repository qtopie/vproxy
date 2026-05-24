package internal

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/qtopie/vproxy/internal/mitm"
	"github.com/qtopie/vproxy/proxy/cgroup"
	"github.com/qtopie/vproxy/proxy/ebpf"
	"github.com/qtopie/vproxy/proxy/iptables"
)

type App struct {
	Config     *Config
	ConfigPath string
	LocalSocks int
	LocalHTTP  int
	LocalTrans int
}

func (a *App) RunServer() {
	sm, ph := a.setupServices()
	sm.Start()
	if err := ph.StartSocks(); err != nil {
		log.Fatalf("Failed to start SOCKS5 proxy: %v", err)
	}
	if err := ph.StartHTTP(); err != nil {
		log.Fatalf("Failed to start HTTP proxy: %v", err)
	}

	best := sm.GetBestServer()
	isUpstreamTProxyAlive := false
	if best != "" {
		if u, err := url.Parse(best); err == nil && u.Scheme == "tproxy" {
			isUpstreamTProxyAlive = true
		}
	}

	if !isUpstreamTProxyAlive {
		if err := ph.StartTransparent(); err != nil {
			log.Fatalf("Failed to start transparent proxy: %v", err)
		}
	} else {
		Debugf("Upstream provides tproxy directly and is ALIVE: %s, not starting local transparent proxy in server mode", best)
	}

	a.PrintConnectivityOK()

	go a.watchConfig(a.ConfigPath, ph)
	go a.monitorNetwork(sm)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	Debugf("Shutting down...")
	ph.Stop()
	sm.Stop()
}

func (a *App) RunWrapper(args []string) {
	Debugf("running command %v", args)

	baseName := filepath.Base(args[0])
	needsEbpf := true
	switch baseName {
	case "curl", "git", "code", "gemini", "antigravity":
		needsEbpf = false
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
			Debugf("No verified upstream yet, defaulting to first: %s", best)
		} else {
			log.Fatal("No upstream servers configured")
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
		ph.Stop()
		sm.Stop()
	}
	defer cleanup()

	// 1. Setup Transparent Proxying Components
	if a.Config.EnableEbpf != nil && *a.Config.EnableEbpf && runtime.GOOS == "linux" && needsEbpf {
		// Check if we have permissions to set SO_MARK (requires CAP_NET_ADMIN)
		if err := ebpf.CheckPermission(); err != nil {
			if os.Getenv("VP_FIX_ATTEMPTED") == "1" {
				log.Fatalf("Fatal: permission setup failed even after attempting fixes: %v", err)
			}

			fmt.Println("\n" + strings.Repeat("=", 60))
			fmt.Printf(" [!] CAPABILITIES REQUIRED\n")
			fmt.Printf(" Transparent proxying requires CAP_NET_ADMIN to set SO_MARK.\n")
			fmt.Printf(" Would you like to run 'sudo setcap' and setup cgroups? [y/N]: ")
			
			var confirm string
			fmt.Scanln(&confirm)
			fmt.Println(strings.Repeat("=", 60))

			if confirm == "y" || confirm == "Y" {
				exe, _ := os.Executable()
				user := os.Getenv("USER")
				if user == "" { user = "root" }
				
				fixCmd := fmt.Sprintf(
					"sudo setcap cap_net_admin,cap_net_bind_service,cap_bpf,cap_sys_resource+ep %s && " +
					"sudo mkdir -p /sys/fs/cgroup/vproxy && " +
					"sudo chown -R %s /sys/fs/cgroup/vproxy",
					exe, user,
				)
				
				fmt.Printf("\n[+] Configuring Permissions...\n")
				exec.Command("bash", "-c", fixCmd).Run()

				fmt.Printf("[+] Permissions updated. Restarting vproxy...\n\n")
				env := os.Environ()
				env = append(env, "VP_FIX_ATTEMPTED=1")
				if err := syscall.Exec(exe, os.Args, env); err != nil {
					log.Fatalf("Failed to restart: %v", err)
				}
			} else {
				log.Fatalf("Fatal: permission check failed: %v", err)
			}
		}

		// Ensure cgroup exists and move current process into it
		if err := cgroup.EnsureVProxyCgroup(); err != nil {
			log.Fatalf("Fatal: failed to setup cgroup: %v", err)
		}
		if err := cgroup.MoveProcessToVProxyCgroup(os.Getpid()); err != nil {
			log.Fatalf("Fatal: failed to move to cgroup: %v", err)
		}

		// Enable SO_MARK on vproxy's own connections to bypass the redirect rules.
		ebpf.SetEnabled(true)
		SetDialerControl(ebpf.GetDialerControl())

		// Attempt eBPF-native redirect (kernel >= 5.7).
		// On failure, fall back to iptables automatically.
		var setupTarget string
		if isUpstreamTProxyAlive {
			setupTarget = bestURL.Host
		} else {
			if err := ph.StartTransparent(); err != nil {
				log.Fatalf("Failed to start transparent bridge: %v", err)
			}
			setupTarget = fmt.Sprintf("%d", ph.TransPort)
		}

		const cgroupPath = "/sys/fs/cgroup/vproxy"
		proxyPort := uint16(ph.TransPort)
		const bypassMark = uint32(0xff)

		if ebpf.IsKernelSupported() {
			r, err := ebpf.Load(cgroupPath, proxyPort, bypassMark)
			if err != nil {
				Debugf("eBPF load failed (%v), falling back to iptables", err)
			} else {
				ebpfResult = r
				Debugf("eBPF redirect active (IPv4/IPv6 TCP+UDP)")
			}
		}

		if ebpfResult == nil {
			// iptables fallback.
			if err := iptables.SetupRules(setupTarget); err != nil {
				log.Fatalf("Fatal: iptables setup failed: %v", err)
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
	cmdName := args[0]
	cmdArgs := args[1:]
	env := os.Environ()
	if IsVerbose() {
		if err := mitm.EnsureCA(); err == nil {
			env = append(env, fmt.Sprintf("SSL_CERT_FILE=%s", mitm.GetCACertPath()))
			Debugf("Tracing CA injected into environment: SSL_CERT_FILE=%s", mitm.GetCACertPath())
		} else {
			Errorf("Failed to initialize dynamic CA: %v", err)
		}
	}

	var finalHTTPProxy string
	var finalSocksProxy string

	var isHTTPTool bool
	baseName = filepath.Base(cmdName)
	switch baseName {
	case "curl", "git", "gemini":
		isHTTPTool = true
	default:
		isHTTPTool = false
	}

	// Determine HTTP proxy requirement
	if bestURL.Scheme == "http" {
		finalHTTPProxy = best
		Debugf("Protocol match: using upstream HTTP proxy directly for %s", cmdName)
	} else {
		if err := ph.StartHTTP(); err != nil {
			log.Fatalf("Failed to start local HTTP bridge: %v", err)
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
				log.Fatalf("Failed to start local SOCKS5 bridge: %v", err)
			}
			finalSocksProxy = fmt.Sprintf("socks5://127.0.0.1:%d", ph.SocksPort)
			Debugf("Protocol mismatch (upstream is %s): started local SOCKS5 bridge at %s", bestURL.Scheme, finalSocksProxy)
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
		env = append(env, fmt.Sprintf("HTTP_PROXY=%s", finalHTTPProxy))
		env = append(env, fmt.Sprintf("HTTPS_PROXY=%s", finalHTTPProxy))
		env = a.appendNoProxyEnv(env)
		newArgs = cmdArgs
	default:
		env = append(env, fmt.Sprintf("http_proxy=%s", finalHTTPProxy))
		env = append(env, fmt.Sprintf("https_proxy=%s", finalHTTPProxy))
		env = append(env, fmt.Sprintf("all_proxy=%s", finalSocksProxy))
		env = append(env, fmt.Sprintf("HTTP_PROXY=%s", finalHTTPProxy))
		env = append(env, fmt.Sprintf("HTTPS_PROXY=%s", finalHTTPProxy))
		env = append(env, fmt.Sprintf("ALL_PROXY=%s", finalSocksProxy))
		env = a.appendNoProxyEnv(env)
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
		log.Fatalf("Command execution failed: %v", err)
	}
}

func (a *App) PrintConnectivityOK() {
	ok := "OK"
	if a.checkColorSupport() {
		ok = "\033[32mOK\033[0m"
	}
	fmt.Printf("vproxy connectivity: %s\n", ok)
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
		log.Fatal("No upstream servers configured")
	}

	rm := NewRuleManager(a.Config.Rules)
	ph := NewProxyHandler(sm, rm, a.LocalSocks, a.LocalHTTP, a.LocalTrans)
	return sm, ph
}

func (a *App) watchConfig(path string, ph *ProxyHandler) {
	stat, err := os.Stat(path)
	if err != nil {
		return
	}
	lastMod := stat.ModTime()
	for {
		time.Sleep(5 * time.Second)
		stat, err := os.Stat(path)
		if err != nil {
			continue
		}
		if stat.ModTime().After(lastMod) {
			lastMod = stat.ModTime()
			cfg, _, err := LoadConfig(path)
			if err == nil {
				ph.UpdateServers(cfg.Upstreams)
				ph.UpdateRules(cfg.Rules)
				Debugf("Config reloaded")
			}
		}
	}
}

func (a *App) monitorNetwork(sm *ServerManager) {
	wasOffline := false
	for {
		time.Sleep(15 * time.Second)
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
