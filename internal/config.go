package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	Upstreams    []string `json:"upstreams"`
	Rules        []string `json:"rules"`
	TestInterval int      `json:"test_interval"` // seconds
	EnableEbpf   *bool    `json:"enable_ebpf,omitempty"`
	DirectDNS    *bool    `json:"direct_dns,omitempty"`
}

// LoadConfig loads the configuration from the given path, with fallbacks to global and local defaults.
// It returns the loaded config and the actual path used.
func LoadConfig(path string) (*Config, string, error) {
	var data []byte
	var err error

	// 1. Resolve the default fallback path (~/.vproxy/config.json)
	home, homeErr := os.UserHomeDir()
	defaultPath := ""
	if homeErr == nil {
		defaultPath = filepath.Join(home, ".vproxy", "config.json")
	}

	// 2. Resolve final path priority
	// Priority: 1. Manually specified path (if path != "vproxy.json")
	//           2. Global config (~/.vproxy/config.json)
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
	if cfg.DirectDNS == nil {
		trueVal := true
		cfg.DirectDNS = &trueVal
	}

	return &cfg, finalPath, nil
}
