//go:build linux
// +build linux

package iptables

import (
	"fmt"
	"os/exec"
	"strings"
)

const (
	bypassMark = 0xff
)

// SetupRules configures iptables rules to redirect TCP traffic from the vproxy cgroup to the proxy port.
func SetupRules(target string) error {
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
	}

	// 4. Redirect all other TCP traffic to the proxy port or target
	var redirectRule string
	targetPort := target
	if !strings.Contains(target, ":") {
		redirectRule = fmt.Sprintf("sudo iptables -t nat -A VPROXY_REDIRECT -p tcp -j REDIRECT --to-ports %s", target)
	} else {
		redirectRule = fmt.Sprintf("sudo iptables -t nat -A VPROXY_REDIRECT -p tcp -j DNAT --to-destination %s", target)
		targetPort = target[strings.LastIndex(target, ":")+1:]
	}
	cmds = append(cmds, redirectRule)

	// 5. Hook the chain into OUTPUT, specifically for the vproxy cgroup
	cmds = append(cmds,
		"sudo iptables -t nat -D OUTPUT -p tcp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT 2>/dev/null || true",
		"sudo iptables -t nat -A OUTPUT -p tcp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT",
	)

	// 6. Setup Policy Routing for UDP TPROXY
	cmds = append(cmds,
		"sudo ip rule add fwmark 1 lookup 100 2>/dev/null || true",
		"sudo ip route add local default dev lo table 100 2>/dev/null || true",
	)

	// 7. Mangle table for marking locally generated UDP packets
	cmds = append(cmds,
		"sudo iptables -t mangle -N VPROXY_MARK 2>/dev/null || true",
		"sudo iptables -t mangle -F VPROXY_MARK",
		fmt.Sprintf("sudo iptables -t mangle -A VPROXY_MARK -m mark --mark 0x%x -j RETURN", bypassMark),
		"sudo iptables -t mangle -A VPROXY_MARK -d 127.0.0.0/8 -j RETURN",
		"sudo iptables -t mangle -A VPROXY_MARK -d 10.0.0.0/8 -j RETURN",
		"sudo iptables -t mangle -A VPROXY_MARK -d 172.16.0.0/12 -j RETURN",
		"sudo iptables -t mangle -A VPROXY_MARK -d 192.168.0.0/16 -j RETURN",
		"sudo iptables -t mangle -A VPROXY_MARK -d 169.254.0.0/16 -j RETURN",
		"sudo iptables -t mangle -A VPROXY_MARK -j MARK --set-mark 1",
		"sudo iptables -t mangle -D OUTPUT -p udp -m cgroup --path \"vproxy\" -j VPROXY_MARK 2>/dev/null || true",
		"sudo iptables -t mangle -A OUTPUT -p udp -m cgroup --path \"vproxy\" -j VPROXY_MARK",
	)

	// 8. Mangle table PREROUTING to apply TPROXY
	cmds = append(cmds,
		"sudo iptables -t mangle -N VPROXY_TPROXY 2>/dev/null || true",
		"sudo iptables -t mangle -F VPROXY_TPROXY",
		fmt.Sprintf("sudo iptables -t mangle -A VPROXY_TPROXY -p udp -m mark --mark 1 -j TPROXY --on-port %s --on-ip 127.0.0.1 --tproxy-mark 1/1", targetPort),
		"sudo iptables -t mangle -D PREROUTING -p udp -m mark --mark 1 -j VPROXY_TPROXY 2>/dev/null || true",
		"sudo iptables -t mangle -A PREROUTING -p udp -m mark --mark 1 -j VPROXY_TPROXY",
	)

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

		"sudo iptables -t mangle -D OUTPUT -p udp -m cgroup --path \"vproxy\" -j VPROXY_MARK 2>/dev/null || true",
		"sudo iptables -t mangle -D PREROUTING -p udp -m mark --mark 1 -j VPROXY_TPROXY 2>/dev/null || true",
		
		"sudo iptables -t mangle -F VPROXY_MARK 2>/dev/null || true",
		"sudo iptables -t mangle -X VPROXY_MARK 2>/dev/null || true",
		
		"sudo iptables -t mangle -F VPROXY_TPROXY 2>/dev/null || true",
		"sudo iptables -t mangle -X VPROXY_TPROXY 2>/dev/null || true",

		"sudo ip rule del fwmark 1 lookup 100 2>/dev/null || true",
		"sudo ip route del local default dev lo table 100 2>/dev/null || true",
	}

	for _, cmdStr := range cmds {
		exec.Command("bash", "-c", cmdStr).Run()
	}

	return nil
}
