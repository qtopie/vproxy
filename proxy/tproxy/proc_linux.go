//go:build linux
// +build linux

package tproxy

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type procCacheEntry struct {
	pid       int
	name      string
	expiresAt time.Time
}

type procCache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[int]procCacheEntry
}

func newProcCache(ttl time.Duration) *procCache {
	return &procCache{
		ttl:     ttl,
		entries: make(map[int]procCacheEntry),
	}
}

func (c *procCache) Get(port int) (string, int, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[port]
	if !ok || time.Now().After(entry.expiresAt) {
		return "", 0, false
	}
	return entry.name, entry.pid, true
}

func (c *procCache) Put(port int, pid int, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Clean up expired entries if map grows large
	if len(c.entries) > 2048 {
		now := time.Now()
		for k, v := range c.entries {
			if now.After(v.expiresAt) {
				delete(c.entries, k)
			}
		}
	}

	c.entries[port] = procCacheEntry{
		pid:       pid,
		name:      name,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Global process cache for Linux driver (TTL: 5 seconds)
var globalProcCache = newProcCache(5 * time.Second)

// RecordProcessMetadata can be called by eBPF or connection hooks to seed the cache with O(1) metadata.
func RecordProcessMetadata(port int, pid int, name string) {
	if port > 0 && pid > 0 && name != "" {
		globalProcCache.Put(port, pid, name)
	}
}

// findSocketInodeByPort parses /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6
// to locate the socket inode corresponding to local port.
func findSocketInodeByPort(port int) (string, error) {
	hexPort := fmt.Sprintf("%04X", port)
	procFiles := []string{
		"/proc/net/tcp",
		"/proc/net/tcp6",
		"/proc/net/udp",
		"/proc/net/udp6",
	}

	for _, pFile := range procFiles {
		f, err := os.Open(pFile)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		isFirst := true
		for scanner.Scan() {
			if isFirst {
				isFirst = false
				continue
			}
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}

			// local_address is field[1] e.g. "0100007F:1FB6"
			localAddr := fields[1]
			if strings.HasSuffix(localAddr, ":"+hexPort) {
				inode := fields[9]
				f.Close()
				if inode != "0" && inode != "" {
					return inode, nil
				}
			}
		}
		f.Close()
	}

	return "", fmt.Errorf("socket inode not found for port %d", port)
}

// findProcessBySocketInode scans /proc/[pid]/fd to find the process owning socket:[inode].
func findProcessBySocketInode(targetInode string) (string, int, error) {
	targetLink := fmt.Sprintf("socket:[%s]", targetInode)

	// First, check current process (fast path)
	selfPID := os.Getpid()
	if name, found := checkPidFd(selfPID, targetLink); found {
		return name, selfPID, nil
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", 0, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || pid == selfPID {
			continue
		}

		if name, found := checkPidFd(pid, targetLink); found {
			return name, pid, nil
		}
	}

	return "", 0, fmt.Errorf("no process found for inode %s", targetInode)
}

func checkPidFd(pid int, targetLink string) (string, bool) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return "", false
	}

	for _, fd := range fds {
		linkPath := filepath.Join(fdDir, fd.Name())
		linkTarget, err := os.Readlink(linkPath)
		if err != nil {
			continue
		}
		if linkTarget == targetLink {
			// Found! Read comm or exe name
			commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
			if err == nil {
				comm := strings.TrimSpace(string(commBytes))
				if comm != "" {
					return comm, true
				}
			}

			// Fallback to exe symlink
			exeTarget, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
			if err == nil && exeTarget != "" {
				return filepath.Base(exeTarget), true
			}

			return fmt.Sprintf("pid-%d", pid), true
		}
	}

	return "", false
}

// ResolveProcessByPort resolves process name and PID on Linux.
func ResolveProcessByPort(port int) (string, int, error) {
	if port <= 0 {
		return "", 0, fmt.Errorf("invalid port %d", port)
	}

	// 1. Check cache first (O(1) fast-path, populated by eBPF or prior /proc scan)
	if name, pid, ok := globalProcCache.Get(port); ok {
		return name, pid, nil
	}

	// 2. Find socket inode
	inode, err := findSocketInodeByPort(port)
	if err != nil {
		return "", 0, err
	}

	// 3. Find process by inode
	name, pid, err := findProcessBySocketInode(inode)
	if err != nil {
		return "", 0, err
	}

	// 4. Cache result
	globalProcCache.Put(port, pid, name)
	return name, pid, nil
}

// ResolveProcessByConn resolves process name and PID from a net.Conn.
func ResolveProcessByConn(conn interface{}) (string, int, error) {
	if conn == nil {
		return "", 0, fmt.Errorf("nil conn")
	}

	type portGetter interface {
		RemoteAddr() net.Addr
		LocalAddr() net.Addr
	}

	c, ok := conn.(portGetter)
	if !ok {
		return "", 0, fmt.Errorf("not a network connection")
	}

	var port int
	if rAddr := c.RemoteAddr(); rAddr != nil {
		switch addr := rAddr.(type) {
		case *net.TCPAddr:
			port = addr.Port
		case *net.UDPAddr:
			port = addr.Port
		}
	}
	if port > 0 {
		if name, pid, err := ResolveProcessByPort(port); err == nil {
			return name, pid, nil
		}
	}

	if lAddr := c.LocalAddr(); lAddr != nil {
		switch addr := lAddr.(type) {
		case *net.TCPAddr:
			port = addr.Port
		case *net.UDPAddr:
			port = addr.Port
		}
	}
	if port > 0 {
		return ResolveProcessByPort(port)
	}

	return "", 0, fmt.Errorf("could not determine port from conn")
}
