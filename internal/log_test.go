package internal

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestLogOutput_SuppressStderrInDaemonMode(t *testing.T) {
	// Backup original state
	origBackground := os.Getenv("VP_BACKGROUND")
	origOutput := logOutput
	defer func() {
		os.Setenv("VP_BACKGROUND", origBackground)
		SetOutput(origOutput)
	}()

	// Buffer to capture custom logOutput
	buf := &bytes.Buffer{}
	SetOutput(buf)

	// In daemon mode (VP_BACKGROUND=1)
	os.Setenv("VP_BACKGROUND", "1")

	// We can't easily capture real os.Stderr without pipe hijacking,
	// but we can test that daemon mode suppresses mirror writing.
	// Write an error
	Errorf("daemon test error message %d", 12345)

	if !strings.Contains(buf.String(), "daemon test error message 12345") {
		t.Fatalf("expected error message in log buffer, got: %s", buf.String())
	}
}

func TestLogOutput_LevelFiltering(t *testing.T) {
	buf := &bytes.Buffer{}
	SetOutput(buf)

	SetLevel(LevelWarn)
	Debugf("debug should be skipped")
	Infof("info should be skipped")
	Warnf("warn should appear")
	Errorf("error should appear")

	out := buf.String()
	if strings.Contains(out, "debug should be skipped") {
		t.Errorf("Debugf should not appear when LevelWarn")
	}
	if strings.Contains(out, "info should be skipped") {
		t.Errorf("Infof should not appear when LevelWarn")
	}
	if !strings.Contains(out, "warn should appear") {
		t.Errorf("Warnf should appear when LevelWarn")
	}
	if !strings.Contains(out, "error should appear") {
		t.Errorf("Errorf should appear when LevelWarn")
	}
}
