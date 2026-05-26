//go:build linux
// +build linux

package iptables

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

const (
	bypassMark = 0xff
)

// SetupRules configures iptables rules to redirect TCP and UDP traffic from the vproxy cgroup.
func SetupRules(target string, isRemoteTProxy bool, upstreamIP net.IP, upstreamPort uint16) error {
	
	// 1. Create nat redirection chain and populate bypasses
	cmds := []string{
		"iptables -t nat -N VPROXY_REDIRECT 2>/dev/null || true",
		"iptables -t nat -F VPROXY_REDIRECT",
		"ip6tables -t nat -N VPROXY_REDIRECT 2>/dev/null || true",
		"ip6tables -t nat -F VPROXY_REDIRECT",
		
		fmt.Sprintf("iptables -t nat -A VPROXY_REDIRECT -m mark --mark 0x%x -j RETURN", bypassMark),
		fmt.Sprintf("ip6tables -t nat -A VPROXY_REDIRECT -m mark --mark 0x%x -j RETURN", bypassMark),
		
		"iptables -t nat -A VPROXY_REDIRECT -d 127.0.0.0/8 -j RETURN",
		"iptables -t nat -A VPROXY_REDIRECT -d 10.0.0.0/8 -j RETURN",
		"iptables -t nat -A VPROXY_REDIRECT -d 172.16.0.0/12 -j RETURN",
		"iptables -t nat -A VPROXY_REDIRECT -d 192.168.0.0/16 -j RETURN",
		"iptables -t nat -A VPROXY_REDIRECT -d 169.254.0.0/16 -j RETURN",
		"ip6tables -t nat -A VPROXY_REDIRECT -d ::1/128 -j RETURN",
		"ip6tables -t nat -A VPROXY_REDIRECT -d fc00::/7 -j RETURN",
		"ip6tables -t nat -A VPROXY_REDIRECT -d fe80::/10 -j RETURN",
	}

	if isRemoteTProxy {
		// ================= REMOTE TPROXY MODE (DNAT ONLY) =================
		targetPort := target[strings.LastIndex(target, ":")+1:]
		
		// TCP Redirect
		cmds = append(cmds,
			fmt.Sprintf("iptables -t nat -A VPROXY_REDIRECT -p tcp -j DNAT --to-destination %s", target),
			fmt.Sprintf("ip6tables -t nat -A VPROXY_REDIRECT -p tcp -j REDIRECT --to-ports %s", targetPort),
		)
		
		// UDP Redirect
		cmds = append(cmds,
			fmt.Sprintf("iptables -t nat -A VPROXY_REDIRECT -p udp -j DNAT --to-destination %s", target),
			fmt.Sprintf("ip6tables -t nat -A VPROXY_REDIRECT -p udp -j REDIRECT --to-ports %s", targetPort),
		)

		// Hook into nat OUTPUT for BOTH tcp and udp
		cmds = append(cmds,
			"iptables -t nat -D OUTPUT -p tcp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT 2>/dev/null || true",
			"iptables -t nat -A OUTPUT -p tcp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT",
			"ip6tables -t nat -D OUTPUT -p tcp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT 2>/dev/null || true",
			"ip6tables -t nat -A OUTPUT -p tcp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT",
			
			"iptables -t nat -D OUTPUT -p udp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT 2>/dev/null || true",
			"iptables -t nat -A OUTPUT -p udp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT",
			"ip6tables -t nat -D OUTPUT -p udp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT 2>/dev/null || true",
			"ip6tables -t nat -A OUTPUT -p udp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT",
		)
	} else {
		// ================= LOCAL SELF-FORWARDING MODE =================
		// TCP REDIRECT to local port
		cmds = append(cmds,
			fmt.Sprintf("iptables -t nat -A VPROXY_REDIRECT -p tcp -j REDIRECT --to-ports %s", target),
			fmt.Sprintf("ip6tables -t nat -A VPROXY_REDIRECT -p tcp -j REDIRECT --to-ports %s", target),
		)
		
		// Hook into nat OUTPUT for TCP only
		cmds = append(cmds,
			"iptables -t nat -D OUTPUT -p tcp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT 2>/dev/null || true",
			"iptables -t nat -A OUTPUT -p tcp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT",
			"ip6tables -t nat -D OUTPUT -p tcp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT 2>/dev/null || true",
			"ip6tables -t nat -A OUTPUT -p tcp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT",
		)
		
		// Setup Policy Routing for UDP TPROXY
		cmds = append(cmds,
			"ip rule add fwmark 1 lookup 100 2>/dev/null || true",
			"ip route add local default dev lo table 100 2>/dev/null || true",
			"ip -6 rule add fwmark 1 lookup 100 2>/dev/null || true",
			"ip -6 route add local default dev lo table 100 2>/dev/null || true",
		)
		
		// Mangle table for marking locally generated UDP packets
		cmds = append(cmds,
			"iptables -t mangle -N VPROXY_MARK 2>/dev/null || true",
			"iptables -t mangle -F VPROXY_MARK",
			"ip6tables -t mangle -N VPROXY_MARK 2>/dev/null || true",
			"ip6tables -t mangle -F VPROXY_MARK",
			
			fmt.Sprintf("iptables -t mangle -A VPROXY_MARK -m mark --mark 0x%x -j RETURN", bypassMark),
			fmt.Sprintf("ip6tables -t mangle -A VPROXY_MARK -m mark --mark 0x%x -j RETURN", bypassMark),
			
			"iptables -t mangle -A VPROXY_MARK -d 127.0.0.0/8 -j RETURN",
			"iptables -t mangle -A VPROXY_MARK -d 10.0.0.0/8 -j RETURN",
			"iptables -t mangle -A VPROXY_MARK -d 172.16.0.0/12 -j RETURN",
			"iptables -t mangle -A VPROXY_MARK -d 192.168.0.0/16 -j RETURN",
			"iptables -t mangle -A VPROXY_MARK -d 169.254.0.0/16 -j RETURN",
			
			"ip6tables -t mangle -A VPROXY_MARK -d ::1/128 -j RETURN",
			"ip6tables -t mangle -A VPROXY_MARK -d fc00::/7 -j RETURN",
			"ip6tables -t mangle -A VPROXY_MARK -d fe80::/10 -j RETURN",
			
			"iptables -t mangle -A VPROXY_MARK -j MARK --set-mark 1",
			"ip6tables -t mangle -A VPROXY_MARK -j MARK --set-mark 1",
			
			"iptables -t mangle -D OUTPUT -p udp -m cgroup --path \"vproxy\" -j VPROXY_MARK 2>/dev/null || true",
			"iptables -t mangle -A OUTPUT -p udp -m cgroup --path \"vproxy\" -j VPROXY_MARK",
			"ip6tables -t mangle -D OUTPUT -p udp -m cgroup --path \"vproxy\" -j VPROXY_MARK 2>/dev/null || true",
			"ip6tables -t mangle -A OUTPUT -p udp -m cgroup --path \"vproxy\" -j VPROXY_MARK",
		)
		
		// Mangle table PREROUTING to apply TPROXY
		cmds = append(cmds,
			"iptables -t mangle -N VPROXY_TPROXY 2>/dev/null || true",
			"iptables -t mangle -F VPROXY_TPROXY",
			"ip6tables -t mangle -N VPROXY_TPROXY 2>/dev/null || true",
			"ip6tables -t mangle -F VPROXY_TPROXY",
			
			fmt.Sprintf("iptables -t mangle -A VPROXY_TPROXY -p udp -m mark --mark 1 -j TPROXY --on-port %s --on-ip 127.0.0.1 --tproxy-mark 1/1", target),
			fmt.Sprintf("ip6tables -t mangle -A VPROXY_TPROXY -p udp -m mark --mark 1 -j TPROXY --on-port %s --on-ip ::1 --tproxy-mark 1/1", target),
			
			"iptables -t mangle -D PREROUTING -p udp -m mark --mark 1 -j VPROXY_TPROXY 2>/dev/null || true",
			"iptables -t mangle -A PREROUTING -p udp -m mark --mark 1 -j VPROXY_TPROXY",
			"ip6tables -t mangle -D PREROUTING -p udp -m mark --mark 1 -j VPROXY_TPROXY 2>/dev/null || true",
			"ip6tables -t mangle -A PREROUTING -p udp -m mark --mark 1 -j VPROXY_TPROXY",
		)
	}

	for _, cmdStr := range cmds {
		if err := exec.Command("bash", "-c", cmdStr).Run(); err != nil {
			return fmt.Errorf("failed to run iptables command '%s': %v", cmdStr, err)
		}
	}

	return nil
}

// CleanupRules removes all iptables and policy routing rules.
func CleanupRules() error {
	cmds := []string{
		// nat OUTPUT hooks
		"iptables -t nat -D OUTPUT -p tcp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT 2>/dev/null || true",
		"ip6tables -t nat -D OUTPUT -p tcp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT 2>/dev/null || true",
		"iptables -t nat -D OUTPUT -p udp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT 2>/dev/null || true",
		"ip6tables -t nat -D OUTPUT -p udp -m cgroup --path \"vproxy\" -j VPROXY_REDIRECT 2>/dev/null || true",
		
		"iptables -t nat -F VPROXY_REDIRECT 2>/dev/null || true",
		"iptables -t nat -X VPROXY_REDIRECT 2>/dev/null || true",
		"ip6tables -t nat -F VPROXY_REDIRECT 2>/dev/null || true",
		"ip6tables -t nat -X VPROXY_REDIRECT 2>/dev/null || true",

		// mangle UDP hooks
		"iptables -t mangle -D OUTPUT -p udp -m cgroup --path \"vproxy\" -j VPROXY_MARK 2>/dev/null || true",
		"iptables -t mangle -D PREROUTING -p udp -m mark --mark 1 -j VPROXY_TPROXY 2>/dev/null || true",
		"ip6tables -t mangle -D OUTPUT -p udp -m cgroup --path \"vproxy\" -j VPROXY_MARK 2>/dev/null || true",
		"ip6tables -t mangle -D PREROUTING -p udp -m mark --mark 1 -j VPROXY_TPROXY 2>/dev/null || true",
		
		"iptables -t mangle -F VPROXY_MARK 2>/dev/null || true",
		"iptables -t mangle -X VPROXY_MARK 2>/dev/null || true",
		"ip6tables -t mangle -F VPROXY_MARK 2>/dev/null || true",
		"ip6tables -t mangle -X VPROXY_MARK 2>/dev/null || true",
		
		"iptables -t mangle -F VPROXY_TPROXY 2>/dev/null || true",
		"iptables -t mangle -X VPROXY_TPROXY 2>/dev/null || true",
		"ip6tables -t mangle -F VPROXY_TPROXY 2>/dev/null || true",
		"ip6tables -t mangle -X VPROXY_TPROXY 2>/dev/null || true",

		// Policy Routing rules
		"ip rule del fwmark 1 lookup 100 2>/dev/null || true",
		"ip route del local default dev lo table 100 2>/dev/null || true",
		"ip -6 rule del fwmark 1 lookup 100 2>/dev/null || true",
		"ip -6 route del local default dev lo table 100 2>/dev/null || true",
	}

	for _, cmdStr := range cmds {
		exec.Command("bash", "-c", cmdStr).Run()
	}

	return nil
}
