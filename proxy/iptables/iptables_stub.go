//go:build !linux
// +build !linux

package iptables

import "net"

func SetupRules(target string, isRemoteTProxy bool, upstreamIP net.IP, upstreamPort uint16) error {
	return nil
}

func CleanupRules() error {
	return nil
}
