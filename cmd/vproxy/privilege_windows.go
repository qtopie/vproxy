//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"

	vlink "github.com/qtopie/vproxy/internal"
	"golang.org/x/sys/windows"
)

func prepareDaemonCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
}

func requireElevatedPrivileges(command string) {
	token := windows.GetCurrentProcessToken()
	elevated := token.IsElevated()
	if !elevated {
		vlink.Fatalf("'%s' command requires Administrator privileges", command)
	}
}

func performPrivilegedInitSetup(string) {}

func isPIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

func stopProcess(process *os.Process) error {
	return process.Kill()
}

