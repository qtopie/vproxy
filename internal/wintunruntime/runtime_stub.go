//go:build !windows

package wintunruntime

import "fmt"

func Ensure() (string, error) {
	return "", fmt.Errorf("Wintun is only supported on Windows")
}
