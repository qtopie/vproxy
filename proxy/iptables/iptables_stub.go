//go:build !linux
// +build !linux

package iptables

func SetupRules(proxyPort int) error {
	return nil
}

func CleanupRules() error {
	return nil
}
