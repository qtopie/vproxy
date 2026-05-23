//go:build linux
// +build linux

package iptables

import (
	"fmt"
	"os/exec"
)

const (
	bypassMark = 0xff
)

// SetupRules configures iptables rules to redirect TCP traffic from the vproxy cgroup to the proxy port.
func SetupRules(proxyPort int) error {
	cmds := []string{
		// 1. Create a new chain in nat table
		"sudo iptables -t nat -N VPROXY_REDIRECT 2>/dev/null || true",
		"sudo iptables -t nat -F VPROXY_REDIRECT",
		// 2. Ignore bypass marked traffic (vproxy's own upstream connections)
		fmt.Sprintf("sudo iptables -t nat -A VPROXY_REDIRECT -m mark --mark 0x%x -j RETURN", bypassMark),
		// 3. Ignore local/loopback traffic
		"sudo iptables -t nat -A VPROXY_REDIRECT -d 127.0.0.0/8 -j RETURN",
		"sudo iptables -t nat -A VPROXY_REDIRECT -d 10.0.0.0/8 -j RETURN",
		"sudo iptables -t nat -A VPROXY_REDIRECT -d 172.16.0.0/12 -j RETURN",
		"sudo iptables -t nat -A VPROXY_REDIRECT -d 192.168.0.0/16 -j RETURN",
		"sudo iptables -t nat -A VPROXY_REDIRECT -d 169.254.0.0/16 -j RETURN",
		// 4. Redirect all other TCP traffic to the proxy port
		fmt.Sprintf("sudo iptables -t nat -A VPROXY_REDIRECT -p tcp -j REDIRECT --to-ports %d", proxyPort),
		// 5. Hook the chain into OUTPUT, specifically for the vproxy cgroup
		"sudo iptables -t nat -D OUTPUT -p tcp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT 2>/dev/null || true",
		"sudo iptables -t nat -A OUTPUT -p tcp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT",
	}

	for _, cmdStr := range cmds {
		if err := exec.Command("bash", "-c", cmdStr).Run(); err != nil {
			return fmt.Errorf("failed to run iptables command '%s': %v", cmdStr, err)
		}
	}

	return nil
}

// CleanupRules removes the iptables rules created by SetupRules.
func CleanupRules() error {
	cmds := []string{
		"sudo iptables -t nat -D OUTPUT -p tcp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT 2>/dev/null || true",
		"sudo iptables -t nat -F VPROXY_REDIRECT 2>/dev/null || true",
		"sudo iptables -t nat -X VPROXY_REDIRECT 2>/dev/null || true",
	}

	for _, cmdStr := range cmds {
		exec.Command("bash", "-c", cmdStr).Run()
	}

	return nil
}
