//go:build !linux
// +build !linux

package iptables

func SetupRules(target string) error {
	return nil
}

func CleanupRules() error {
	return nil
}
