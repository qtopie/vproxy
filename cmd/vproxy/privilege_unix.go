//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	vlink "github.com/qtopie/vproxy/internal"
)

func requireElevatedPrivileges(command string) {
	if os.Geteuid() != 0 {
		vlink.Fatalf("'%s' command requires root privileges", command)
	}
}

func performPrivilegedInitSetup(binary string) {
	if runtime.GOOS != "linux" {
		return
	}

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

func stopProcess(process *os.Process) error {
	return process.Signal(syscall.SIGTERM)
}
