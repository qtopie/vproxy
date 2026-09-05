package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type Config struct {
	Upstreams    []string `json:"upstreams"`
	Rules        []string `json:"rules"`
	TestInterval int      `json:"test_interval"` // seconds
	WebPort        int      `json:"web_port,omitempty"`
	EnableEbpf     *bool    `json:"enable_ebpf,omitempty"`
	DirectDNS      *bool    `json:"direct_dns,omitempty"`
	DialTimeoutMs  *int     `json:"dial_timeout_ms,omitempty"`
	DialRetryCount *int     `json:"dial_retry_count,omitempty"`
	BypassNodes    []string `json:"bypass_nodes,omitempty"`
}

// LoadConfig loads the configuration from the given path, with fallbacks to global and local defaults.
// It returns the loaded config and the actual path used.
func LoadConfig(path string) (*Config, string, error) {
	var data []byte
	var err error

	// 1. Resolve the default fallback path
	defaultPath := ""
	if runtime.GOOS == "linux" {
		defaultPath = "/etc/vproxy/config.json"
	} else {
		home, homeErr := os.UserHomeDir()
		if homeErr == nil {
			defaultPath = filepath.Join(home, ".vproxy", "config.json")
		}
	}

	// 2. Resolve final path priority
	// Priority: 1. Manually specified path (if path != "vproxy.json")
	//           2. Global config (e.g. /etc/vproxy/config.json or ~/.vproxy/config.json)
	//           3. Local directory (vproxy.json)

	finalPath := path
	if path == "vproxy.json" && defaultPath != "" {
		// If user didn't change default "vproxy.json", try global first
		if _, err := os.Stat(defaultPath); err == nil {
			finalPath = defaultPath
		}
	}

	// 3. Attempt to read
	if _, err = os.Stat(finalPath); err == nil {
		data, err = os.ReadFile(finalPath)
	} else if finalPath != path {
		// Fallback to local if global wasn't found
		if _, err = os.Stat(path); err == nil {
			data, err = os.ReadFile(path)
			finalPath = path
		}
	}

	// 4. Handle cases where no file was found
	if data == nil {
		return nil, "", fmt.Errorf("no configuration found (checked %s and %s)", finalPath, path)
	}

	// 5. Parse the data
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, "", err
	}

	// 6. Apply defaults if missing
	if cfg.TestInterval == 0 {
		cfg.TestInterval = 30
	}
	if cfg.WebPort == 0 {
		cfg.WebPort = 8899
	}
	if cfg.DirectDNS == nil {
		trueVal := true
		cfg.DirectDNS = &trueVal
	}
	if cfg.DialTimeoutMs == nil {
		fiveSec := 5000
		cfg.DialTimeoutMs = &fiveSec
	}
	if cfg.DialRetryCount == nil {
		threeAttempts := 3
		cfg.DialRetryCount = &threeAttempts
	}

	return &cfg, finalPath, nil
}

// GetPIDFilePath returns the platform-specific path for the PID file.
// It uses a shared location so that both privileged and unprivileged users
// can check the daemon's status.
func GetPIDFilePath() string {
	if runtime.GOOS == "windows" {
		// On Windows, use a subfolder in ProgramData for shared access.
		// Fallback to os.TempDir() if ProgramData is not accessible.
		programData := os.Getenv("ProgramData")
		if programData != "" {
			path := filepath.Join(programData, "vproxy")
			_ = os.MkdirAll(path, 0755)
			return filepath.Join(path, "vproxy.pid")
		}
		return filepath.Join(os.TempDir(), "vproxy.pid")
	}
	// Unix systems: use /tmp as it is globally writable and shared.
	return "/tmp/vproxy.pid"
}
