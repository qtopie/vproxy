package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	vlink "github.com/qtopie/vproxy/internal"
	"github.com/qtopie/vproxy/proxy/tproxy"
)

var (
	configPath = flag.String("c", "vproxy.json", "path to config file")
	verbose    = flag.Bool("v", false, "verbose mode")
	localHTTP  = flag.Int("http", 8118, "local HTTP proxy port")
	localSocks = flag.Int("socks", 1080, "local SOCKS5 proxy port")
	localTrans = flag.Int("trans", 10080, "local transparent proxy port")
	useTun     = flag.Bool("tun", false, "enable TUN mode (Linux only)")
)

var (
	pidFile = filepath.Join(os.TempDir(), "vproxy.pid")
)

func main() {
	flag.Parse()
	args := flag.Args()

	if *verbose {
		vlink.SetVerbose(true)
	}
	if *useTun {
		os.Setenv("VP_USE_TUN", "1")
	}

	if len(args) == 0 {
		printUsage()
		return
	}

	command := args[0]

	switch command {
	case "status":
		fmt.Printf("vproxy status:\n")

		// 1. Check for background daemon via PID file
		data, err := os.ReadFile(pidFile)
		if err == nil {
			pid, _ := strconv.Atoi(string(data))
			if _, err := os.FindProcess(pid); err == nil {
				fmt.Printf("  Background Daemon: Running (PID: %d)\n", pid)

				// 2. Try to get detailed status via IPC
				if resp, err := vlink.RequestStatus(); err == nil {
					fmt.Printf("  Version:           %s\n", resp.Version)
					fmt.Printf("  Uptime:            %s\n", resp.Uptime)
				} else {
					fmt.Printf("  IPC Detail:        Unavailable (%v)\n", err)
				}
			} else {
				fmt.Printf("  Background Daemon: Stale PID file found (PID: %d)\n", pid)
			}
		} else {
			fmt.Printf("  Background Daemon: Not running\n")
		}

		fmt.Printf("  Config Path:       %s\n", *configPath)
		return

	case "clean":
		if os.Geteuid() != 0 {
			vlink.Fatal("'clean' command requires sudo privileges")
		}
		stopBackgroundServer()
		vlink.SetVerbose(*verbose)
		tproxy.Cleanup()
		fmt.Println("vproxy: environment cleaned.")
		return

	case "stop":
		stopBackgroundServer()
		fmt.Println("vproxy: background server stopped.")
		return

	case "init":
		if os.Geteuid() != 0 {
			vlink.Fatal("'init' command requires sudo privileges")
		}

		// Fail fast: verify configuration exists and is valid before starting daemon
		_, resolvedPath, err := vlink.LoadConfig(*configPath)
		if err != nil {
			vlink.Fatalf("init failed: %v", err)
		}

		binary, err := os.Executable()
		if err == nil {
			sudoUser := os.Getenv("SUDO_USER")
			if sudoUser == "" {
				sudoUser = "root"
			}

			fmt.Printf("vproxy: Setting up BPF capabilities for binary %s\n", binary)
			exec.Command("setcap", "cap_net_admin,cap_net_bind_service,cap_bpf,cap_sys_resource+ep", binary).Run()

			fmt.Println("vproxy: Setting up cgroups directory /sys/fs/cgroup/vproxy")
			exec.Command("mkdir", "-p", "/sys/fs/cgroup/vproxy").Run()
			exec.Command("chown", "-R", sudoUser, "/sys/fs/cgroup/vproxy").Run()
		}

		startBackgroundServer(resolvedPath)
		return

	case "start":
		cfg, finalPath, err := vlink.LoadConfig(*configPath)
		if err != nil {
			vlink.Fatalf("Failed to load config: %v", err)
		}
		vproxy := &vlink.App{
			Config:     cfg,
			ConfigPath: finalPath,
			LocalSocks: *localSocks,
			LocalHTTP:  *localHTTP,
			LocalTrans: *localTrans,
		}
		vproxy.RunServer()
		return
	}

	// Not a built-in subcommand, treat as a wrapper: vproxy curl ...
	cfg, finalPath, err := vlink.LoadConfig(*configPath)
	if err != nil {
		vlink.Fatalf("Failed to load config: %v", err)
	}

	isVerbose := (verbose != nil && *verbose) || os.Getenv("VP_VERBOSE") == "1"
	if isVerbose {
		vlink.SetVerbose(true)
		vlink.Debugf("Verbose mode enabled (VP_VERBOSE=1 or -v)")
	}

	// Redirect logs to a file to keep console clean for the wrapped command
	logPath := filepath.Join(os.TempDir(), fmt.Sprintf("vproxy-%d.log", os.Getpid()))
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		vlink.SetOutput(f)
		fmt.Fprintf(os.Stderr, "vproxy: logging to %s\n", logPath)
	} else {
		fmt.Fprintf(os.Stderr, "vproxy: failed to open log file %s: %v\n", logPath, err)
	}

	vproxy := &vlink.App{
		Config:     cfg,
		ConfigPath: finalPath,
		LocalSocks: *localSocks,
		LocalHTTP:  *localHTTP,
		LocalTrans: *localTrans,
	}
	vlink.Debugf("vproxy app initialized with config: %s", finalPath)

	// If it's a command like 'vproxy agy'
	cmdName := args[0]
	vlink.Debugf("Target command: %s", cmdName)

	// 1. Ensure the command is in our PROCESS proxy list
	ensureProcessInConfig(finalPath, cfg, cmdName)

	// 2. Run the command.
	vproxy.RunWrapper(args)
}

func printUsage() {
	fmt.Println("Usage: vproxy [options] <command> [args...]")
	fmt.Println("\nCommands:")
	fmt.Println("  start         Run vproxy server in foreground (includes Web UI)")
	fmt.Println("  init          Perform privileged setup and start background daemon")
	fmt.Println("  stop          Stop the background daemon")
	fmt.Println("  status        Display current server status")
	fmt.Println("  clean         Clean up environment and stop daemon (requires sudo)")
	fmt.Println("  <cmd> [args]  Run an external command through vproxy (e.g., vproxy curl ...)")
	fmt.Println("\nOptions:")
	flag.PrintDefaults()
}

func startBackgroundServer(config string) {
	// Check if already running
	if _, err := os.Stat(pidFile); err == nil {
		fmt.Fprintln(os.Stderr, "vproxy is already running. Run 'vproxy clean' first if you want to restart.")
		return
	}

	binary, _ := os.Executable()
	bgArgs := []string{"-c", config, "start"}
	if *useTun {
		bgArgs = append(bgArgs, "-tun")
	}
	if *verbose {
		bgArgs = append(bgArgs, "-v")
	}
	cmd := exec.Command(binary, bgArgs...)
	// Inherit environment but set a marker
	cmd.Env = append(os.Environ(), "VP_BACKGROUND=1")
	
	// Open log file for background process in the system temp directory so it can be inspected
	logFile := filepath.Join(os.TempDir(), "vproxy.log")
	f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	cmd.Stdout = f
	cmd.Stderr = f
	
	err := cmd.Start()
	if err != nil {
		vlink.Fatalf("Failed to start background server: %v", err)
	}

	os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0644)
	fmt.Fprintf(os.Stderr, "vproxy: started in background (PID: %d, Log: %s)\n", cmd.Process.Pid, logFile)
	fmt.Fprintln(os.Stderr, "vproxy: TUN environment initialized.")
}

func stopBackgroundServer() {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return
	}
	pid, _ := strconv.Atoi(string(data))
	process, err := os.FindProcess(pid)
	if err == nil {
		process.Signal(syscall.SIGTERM)
		// Wait a bit for cleanup
		time.Sleep(1 * time.Second)
	}
	os.Remove(pidFile)
}

func ensureProcessInConfig(path string, cfg *vlink.Config, proc string) {
	rule := fmt.Sprintf("PROCESS,%s,PROXY", proc)
	exists := false
	for _, r := range cfg.Rules {
		if strings.Contains(r, proc) {
			exists = true
			break
		}
	}
	if !exists {
		cfg.Rules = append(cfg.Rules, rule)
		// Save back to config
		data, _ := json.MarshalIndent(cfg, "", "  ")
		os.WriteFile(path, data, 0644)
		fmt.Fprintf(os.Stderr, "vproxy: added '%s' to proxy rules\n", proc)
	}
}
