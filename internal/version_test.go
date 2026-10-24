package internal

import (
	"strings"
	"testing"
)

func TestGetVersion_ExplicitPriority(t *testing.T) {
	defer ResetVersionForTesting("", "", "")

	ResetVersionForTesting("v1.5.0", "abcdef123456", "2026-10-24T00:00:00Z")
	info := GetVersionInfo()

	if info.Version != "v1.5.0" {
		t.Fatalf("expected version v1.5.0, got %s", info.Version)
	}
	if info.GitCommit != "abcdef123456" {
		t.Fatalf("expected commit abcdef123456, got %s", info.GitCommit)
	}
	if info.BuildDate != "2026-10-24T00:00:00Z" {
		t.Fatalf("expected build date 2026-10-24T00:00:00Z, got %s", info.BuildDate)
	}
	if info.GoVersion == "" || !strings.HasPrefix(info.GoVersion, "go") {
		t.Fatalf("expected valid GoVersion, got %s", info.GoVersion)
	}
	if !strings.Contains(info.Platform, "/") {
		t.Fatalf("expected Platform formatted as os/arch, got %s", info.Platform)
	}
}

func TestGetVersion_VCSResolution(t *testing.T) {
	defer ResetVersionForTesting("", "", "")

	// Clear explicit version to test automatic VCS resolution
	ResetVersionForTesting("", "", "")
	info := GetVersionInfo()

	if info.Version == "" {
		t.Fatalf("version should not be empty")
	}
	// When built in a git repo via go test, buildinfo should contain git info or fallback to dev
	t.Logf("Resolved version: %s (commit: %s, dirty: %v, go: %s, platform: %s)",
		info.Version, info.GitCommit, info.GitDirty, info.GoVersion, info.Platform)

	if GetVersion() != info.Version {
		t.Fatalf("GetVersion() != GetVersionInfo().Version")
	}
}

func TestBuildVersionInfo_Fallbacks(t *testing.T) {
	// 1. When explicit commit is provided without version
	v1 := buildVersionInfo("", "1234567890abcdef", "")
	if !strings.HasPrefix(v1.Version, "1234567") {
		t.Fatalf("expected short commit 1234567 in version, got %s", v1.Version)
	}

	// 2. Pure fallback
	v2 := buildVersionInfo("v2.0.0", "", "")
	if v2.Version != "v2.0.0" {
		t.Fatalf("expected v2.0.0, got %s", v2.Version)
	}
}
