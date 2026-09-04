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
