//go:build !windows
// +build !windows

package main

import (
	"os/exec"
	"testing"
)

func TestPrepareDaemonCommand_Setsid(t *testing.T) {
	cmd := exec.Command("sleep", "1")
	prepareDaemonCommand(cmd)

	if cmd.SysProcAttr == nil {
		t.Fatal("expected cmd.SysProcAttr to be non-nil")
	}
	if !cmd.SysProcAttr.Setsid {
		t.Errorf("expected cmd.SysProcAttr.Setsid to be true, got false")
	}
}
