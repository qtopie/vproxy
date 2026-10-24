package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func captureStdout(f func()) string {
	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outC <- buf.String()
	}()

	f()

	_ = w.Close()
	os.Stdout = oldStdout
	out := <-outC
	_ = r.Close()
	return out
}

func TestPrintVersion(t *testing.T) {
	out := captureStdout(func() {
		printVersion()
	})

	if !strings.HasPrefix(out, "vproxy version ") {
		t.Fatalf("expected version prefix 'vproxy version ', got: %s", out)
	}
	if !strings.Contains(out, "go:") {
		t.Fatalf("expected Go runtime version in output, got: %s", out)
	}
}
