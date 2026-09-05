package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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

func init() {
	flag.StringVar(configPath, "config", "vproxy.json", "path to config file (alias for -c)")
}

func main() {
	flag.Parse()
	args := flag.Args()

	pidFile := vlink.GetPIDFilePath()

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

				// 2. Try to get detailed status via IPC (Linux only; Windows uses Wintun TUN mode without Unix socket IPC)
				if runtime.GOOS == "windows" {
					fmt.Printf("  Mode:              Windows TUN (Wintun)\n")
				} else if resp, err := vlink.RequestStatus(); err == nil {
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
		requireElevatedPrivileges("clean")
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
		requireElevatedPrivileges("init")

		// Fail fast: verify configuration exists and is valid before starting daemon
		_, resolvedPath, err := vlink.LoadConfig(*configPath)
		if err != nil {
			vlink.Fatalf("init failed: %v", err)
		}

		binary, err := os.Executable()
		if err == nil {
			performPrivilegedInitSetup(binary)
		}

		if err := startBackgroundServer(resolvedPath, pidFile); err != nil {
			vlink.Fatalf("init failed: %v", err)
		}
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
	isVerbose := (verbose != nil && *verbose) || os.Getenv("VP_VERBOSE") == "1"
	if isVerbose {
		vlink.SetVerbose(true)
	}

	// Redirect logs to a file to keep console clean for the wrapped command,
	// unless verbose mode is requested.
	if !isVerbose {
		logPath := filepath.Join(os.TempDir(), fmt.Sprintf("vproxy-%d.log", os.Getpid()))
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			vlink.SetOutput(f)
			vlink.Infof("vproxy: logging to %s", logPath)
		} else {
			fmt.Fprintf(os.Stderr, "vproxy: failed to open log file %s: %v\n", logPath, err)
		}
	}

	if isVerbose {
		vlink.Debugf("Verbose mode enabled (VP_VERBOSE=1 or -v)")
	}

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
	fmt.Println("  clean         Clean up environment and stop daemon (requires elevation)")
	fmt.Println("  <cmd> [args]  Run an external command through vproxy (e.g., vproxy curl ...)")
	fmt.Println("\nOptions:")
	flag.PrintDefaults()
}

func startBackgroundServer(config, pidFile string) error {
	// Check if already running
	if _, err := os.Stat(pidFile); err == nil {
		fmt.Fprintln(os.Stderr, "vproxy is already running. Run 'vproxy clean' first if you want to restart.")
		return nil
	}

	binary, _ := os.Executable()
	bgArgs := []string{"-c", config}
	if *useTun {
		bgArgs = append(bgArgs, "-tun")
	}
	if *verbose {
		bgArgs = append(bgArgs, "-v")
	}
	bgArgs = append(bgArgs, "start")
	readyFile := filepath.Join(os.TempDir(), fmt.Sprintf("vproxy-ready-%d", time.Now().UnixNano()))
	_ = os.Remove(readyFile)
	cmd := exec.Command(binary, bgArgs...)
	// Inherit environment but set a marker
	cmd.Env = append(os.Environ(), "VP_BACKGROUND=1", "VP_READY_FILE="+readyFile)

	// Open log file for background process in the system temp directory so it can be inspected
	logFile := filepath.Join(os.TempDir(), "vproxy.log")
	f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	cmd.Stdout = f
	cmd.Stderr = f

	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start background server: %w", err)
	}

	os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0644)
	fmt.Fprintf(os.Stderr, "vproxy: started in background (PID: %d, Log: %s)\n", cmd.Process.Pid, logFile)
	if runtime.GOOS != "windows" {
		fmt.Fprintln(os.Stderr, "vproxy: environment initialized.")
		return nil
	}

	exitCh := make(chan error, 1)
	go func() {
		exitCh <- cmd.Wait()
	}()
	startupTimeout := 15 * time.Second
	if err := waitForReadyFile(readyFile, startupTimeout, func() bool {
		select {
		case exitErr := <-exitCh:
			exitCh <- exitErr
			return false
		default:
			return true
		}
	}); err != nil {
		_ = cmd.Process.Kill()
		<-exitCh
		_ = os.Remove(pidFile)
		tproxy.Cleanup()
		return fmt.Errorf("background server did not become ready within %s: %w", startupTimeout, err)
	}
	_ = os.Remove(readyFile)
	fmt.Fprintln(os.Stderr, "vproxy: TUN environment initialized and ready.")
	return nil
}

func waitForReadyFile(path string, timeout time.Duration, processAlive func() bool) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if !processAlive() {
			return fmt.Errorf("background server exited before signaling readiness")
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("readiness file was not created")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func stopBackgroundServer() {
	pidFile := vlink.GetPIDFilePath()
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return
	}
	pid, _ := strconv.Atoi(string(data))
	process, err := os.FindProcess(pid)
	if err == nil {
		stopProcess(process)
		// Wait a bit for cleanup
		time.Sleep(1 * time.Second)
	}
	os.Remove(pidFile)
	tproxy.Cleanup()
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
		// Prepend the rule to ensure it has the highest priority
		cfg.Rules = append([]string{rule}, cfg.Rules...)
		// Save back to config
		data, _ := json.MarshalIndent(cfg, "", "  ")
		os.WriteFile(path, data, 0644)
		vlink.Infof("vproxy: added '%s' to proxy rules (priority: high)", proc)
	}
}
