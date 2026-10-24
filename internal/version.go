package internal

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
)

var (
	// Version can be injected at build time via -ldflags "-X github.com/qtopie/vproxy/internal.Version=v1.0.9"
	Version   = ""
	GitCommit = ""
	BuildDate = ""

	versionMu   sync.Mutex
	cachedInfo  *VersionInfo
)

type VersionInfo struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	GitDirty  bool   `json:"git_dirty"`
	BuildDate string `json:"build_date,omitempty"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

func buildVersionInfo(explicitVersion, explicitCommit, explicitDate string) VersionInfo {
	info := VersionInfo{
		Version:   explicitVersion,
		GitCommit: explicitCommit,
		BuildDate: explicitDate,
		GoVersion: runtime.Version(),
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}

	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.GitCommit == "" {
					info.GitCommit = s.Value
				}
			case "vcs.time":
				if info.BuildDate == "" {
					info.BuildDate = s.Value
				}
			case "vcs.modified":
				if s.Value == "true" {
					info.GitDirty = true
				}
			}
		}
	}

	if info.Version == "" {
		if info.GitCommit != "" {
			shortCommit := info.GitCommit
			if len(shortCommit) > 7 {
				shortCommit = shortCommit[:7]
			}
			if info.GitDirty {
				info.Version = shortCommit + "-dirty"
			} else {
				info.Version = shortCommit
			}
		} else {
			info.Version = "dev"
		}
	}

	return info
}

// GetVersion returns the canonical version string (e.g., "v1.0.9" or short commit "26e5bdc").
func GetVersion() string {
	return GetVersionInfo().Version
}

// GetVersionInfo returns complete structured version metadata.
func GetVersionInfo() VersionInfo {
	versionMu.Lock()
	defer versionMu.Unlock()
	if cachedInfo == nil {
		info := buildVersionInfo(Version, GitCommit, BuildDate)
		cachedInfo = &info
	}
	return *cachedInfo
}

// ResetVersionForTesting clears the cached version info (for test use only).
func ResetVersionForTesting(testVersion, testCommit, testDate string) {
	versionMu.Lock()
	defer versionMu.Unlock()
	Version = testVersion
	GitCommit = testCommit
	BuildDate = testDate
	cachedInfo = nil
}
