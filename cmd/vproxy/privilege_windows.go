//go:build windows

package main

import (
	"os"

	vlink "github.com/qtopie/vproxy/internal"
	"golang.org/x/sys/windows"
)

func requireElevatedPrivileges(command string) {
	token := windows.GetCurrentProcessToken()
	elevated := token.IsElevated()
	if !elevated {
		vlink.Fatalf("'%s' command requires Administrator privileges", command)
	}
}

func performPrivilegedInitSetup(string) {}

func stopProcess(process *os.Process) error {
	return process.Kill()
}
