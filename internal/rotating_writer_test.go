package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingWriter_SizeBoundedAndRotates(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "test.log")

	// MaxSize: 1000 bytes, MaxBackups: 2
	w, err := NewRotatingWriter(logPath, 1000, 2)
	if err != nil {
		t.Fatalf("failed to create rotating writer: %v", err)
	}
	defer w.Close()

	chunk := strings.Repeat("A", 400) + "\n"

	// Write chunk 1 (~401 bytes)
	if _, err := w.Write([]byte(chunk)); err != nil {
		t.Fatalf("write 1 failed: %v", err)
	}

	// Write chunk 2 (~401 bytes, total ~802 bytes)
	if _, err := w.Write([]byte(chunk)); err != nil {
		t.Fatalf("write 2 failed: %v", err)
	}

	// At this point test.log is ~802 bytes, no rotation yet
	if _, err := os.Stat(logPath + ".1"); !os.IsNotExist(err) {
		t.Fatalf("expected test.log.1 to not exist yet")
	}

	// Write chunk 3 (~401 bytes, would exceed 1000 bytes -> triggers rotation)
	if _, err := w.Write([]byte(chunk)); err != nil {
		t.Fatalf("write 3 failed: %v", err)
	}

	// test.log.1 should now exist with ~802 bytes, test.log should have ~401 bytes
	info1, err := os.Stat(logPath + ".1")
	if err != nil {
		t.Fatalf("expected test.log.1 to exist after rotation: %v", err)
	}
	if info1.Size() < 800 {
		t.Errorf("expected test.log.1 to have >= 800 bytes, got %d", info1.Size())
	}

	currInfo, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("expected test.log to exist: %v", err)
	}
	if currInfo.Size() > 600 {
		t.Errorf("expected test.log to have ~401 bytes, got %d", currInfo.Size())
	}

	// Trigger second rotation: write 2 more chunks
	if _, err := w.Write([]byte(chunk)); err != nil {
		t.Fatalf("write 4 failed: %v", err)
	}
	if _, err := w.Write([]byte(chunk)); err != nil {
		t.Fatalf("write 5 failed: %v", err)
	}

	// Now test.log.2 and test.log.1 should exist
	if _, err := os.Stat(logPath + ".2"); err != nil {
		t.Fatalf("expected test.log.2 to exist: %v", err)
	}

	// Trigger third rotation: write 2 more chunks
	if _, err := w.Write([]byte(chunk)); err != nil {
		t.Fatalf("write 6 failed: %v", err)
	}
	if _, err := w.Write([]byte(chunk)); err != nil {
		t.Fatalf("write 7 failed: %v", err)
	}

	// MaxBackups is 2, so test.log.3 must NOT exist
	if _, err := os.Stat(logPath + ".3"); !os.IsNotExist(err) {
		t.Fatalf("expected test.log.3 to not exist (MaxBackups=2)")
	}

	// Total disk usage of all test.log* files should be bounded <= 3500 bytes
	var totalBytes int64
	for i := 0; i <= 2; i++ {
		p := logPath
		if i > 0 {
			p = fmt.Sprintf("%s.%d", logPath, i)
		}
		if fi, err := os.Stat(p); err == nil {
			totalBytes += fi.Size()
		}
	}
	if totalBytes > 3500 {
		t.Errorf("expected bounded total size <= 3500 bytes, got %d", totalBytes)
	}
}
