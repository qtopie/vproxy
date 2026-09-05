//go:build windows

package wintunruntime

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

//go:embed embed/wintun.amd64.dll
var wintunDLL []byte

const versionedRuntimeDir = "vproxy-wintun-0.14.1"

// Ensure installs the bundled Wintun runtime and makes it discoverable by
// LoadLibrary calls made by the WireGuard TUN package.
func Ensure() (string, error) {
	// Strategy 1: Attempt to place wintun.dll in the same directory as the executable.
	// This naturally satisfies LOAD_LIBRARY_SEARCH_APPLICATION_DIR without requiring
	// extra DLL search path manipulation.
	if exePath, err := os.Executable(); err == nil && exePath != "" {
		appDir := filepath.Dir(exePath)
		targetPath := filepath.Join(appDir, "wintun.dll")
		// Check if it already exists or if we can write to it
		if fi, err := os.Stat(targetPath); err == nil && fi.Size() > 0 {
			_ = windows.SetDllDirectory(appDir)
			return targetPath, nil
		}
		if err := os.WriteFile(targetPath, wintunDLL, 0644); err == nil {
			_ = windows.SetDllDirectory(appDir)
			return targetPath, nil
		}
	}

	// Strategy 2: Fallback to versioned directory in user Temp directory.
	runtimeDir := filepath.Join(os.TempDir(), versionedRuntimeDir)
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		return "", fmt.Errorf("create Wintun runtime directory: %w", err)
	}

	dllPath := filepath.Join(runtimeDir, "wintun.dll")
	if err := os.WriteFile(dllPath, wintunDLL, 0600); err != nil {
		return "", fmt.Errorf("write bundled Wintun 0.14.1: %w", err)
	}
	if err := windows.SetDllDirectory(runtimeDir); err != nil {
		return "", fmt.Errorf("configure Wintun DLL directory: %w", err)
	}
	return dllPath, nil
}

