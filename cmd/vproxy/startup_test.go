package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWaitForReadyFile(t *testing.T) {
	dir := t.TempDir()
	readyFile := filepath.Join(dir, "ready")
	go func() {
		time.Sleep(10 * time.Millisecond)
		_ = os.WriteFile(readyFile, []byte("ready"), 0600)
	}()

	if err := waitForReadyFile(readyFile, 500*time.Millisecond, func() bool { return true }); err != nil {
		t.Fatalf("waitForReadyFile returned an error: %v", err)
	}
}

func TestWaitForReadyFileReportsProcessExit(t *testing.T) {
	dir := t.TempDir()
	readyFile := filepath.Join(dir, "ready")

	if err := waitForReadyFile(readyFile, 500*time.Millisecond, func() bool { return false }); err == nil {
		t.Fatal("waitForReadyFile returned nil after the process exited")
	}
}
