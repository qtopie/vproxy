package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
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

	// Handle 'clean' command
	if len(args) > 0 && args[0] == "clean" {
		if os.Geteuid() != 0 {
			log.Fatal("'clean' command requires sudo privileges")
		}
		stopBackgroundServer()
		vlink.SetVerbose(*verbose)
		tproxy.Cleanup()
		fmt.Println("vproxy: environment cleaned.")
		return
	}

	// Handle 'init' command
	if len(args) > 0 && args[0] == "init" {
		if os.Geteuid() != 0 {
			log.Fatal("'init' command requires sudo privileges")
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

		startBackgroundServer(*configPath)
		return
	}

	cfg, finalPath, err := vlink.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	isVerbose := (verbose != nil && *verbose) || os.Getenv("VP_VERBOSE") == "1"
	if isVerbose {
		vlink.SetVerbose(true)
		vlink.Debugf("Verbose mode enabled (VP_VERBOSE=1 or -v)")
	}

	// Redirect logs to a file to keep console clean for the wrapped command
	logPath := filepath.Join(os.TempDir(), fmt.Sprintf("vproxy-%d.log", os.Getpid()))
	if len(args) > 0 {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			vlink.SetOutput(f)
			fmt.Fprintf(os.Stderr, "vproxy: logging to %s\n", logPath)
		} else {
			fmt.Fprintf(os.Stderr, "vproxy: failed to open log file %s: %v\n", logPath, err)
		}
	}

	vproxy := &vlink.App{
		Config:     cfg,
		ConfigPath: finalPath,
		LocalSocks: *localSocks,
		LocalHTTP:  *localHTTP,
		LocalTrans: *localTrans,
	}
	vlink.Debugf("vproxy app initialized with config: %s", finalPath)

	if len(args) > 0 {
		// If it's a command like 'vproxy agy'
		cmdName := args[0]
		vlink.Debugf("Target command: %s", cmdName)
		
		// 1. Ensure the command is in our PROCESS proxy list
		ensureProcessInConfig(finalPath, cfg, cmdName)
		
		// 2. Run the command. 
		vproxy.RunWrapper(args)
		return
	}

	// Default: Run as foreground server
	vproxy.RunServer()
}

func startBackgroundServer(config string) {
	// Check if already running
	if _, err := os.Stat(pidFile); err == nil {
		fmt.Println("vproxy is already running. Run 'vproxy clean' first if you want to restart.")
		return
	}

	binary, _ := os.Executable()
	bgArgs := []string{"-c", config}
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
		log.Fatalf("Failed to start background server: %v", err)
	}

	os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0644)
	fmt.Printf("vproxy: started in background (PID: %d, Log: %s)\n", cmd.Process.Pid, logFile)
	fmt.Println("vproxy: TUN environment initialized.")
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
		fmt.Printf("vproxy: added '%s' to proxy rules\n", proc)
	}
}

