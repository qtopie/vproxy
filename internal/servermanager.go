package internal

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ServerManager holds a list of servers, periodically tests them, and provides the best one.
type ServerManager struct {
	servers      []string
	selfPorts    []int
	activeServer string
	lastSuccess  time.Time
	mu           sync.RWMutex
	testInterval time.Duration
	testTimeout  time.Duration
	stopChan     chan struct{}
	stopOnce     sync.Once
}

// NewServerManager creates a new ServerManager.
func NewServerManager(servers []string, testInterval, testTimeout time.Duration) *ServerManager {
	return &ServerManager{
		servers:      servers,
		testInterval: testInterval,
		testTimeout:  testTimeout,
		stopChan:     make(chan struct{}),
	}
}

// Start begins the periodic testing of servers in a background goroutine.
// It performs an initial synchronous probe before returning, which ensures
// GetBestServer() is ready immediately. Use StartAsync for latency-sensitive
// callers that can tolerate falling back to the first configured server.
func (sm *ServerManager) Start() {
	log.Println("ServerManager: Starting...")
	// Perform an initial test synchronously.
	sm.testServers()

	go func() {
		ticker := time.NewTicker(sm.testInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				sm.testServers()
			case <-sm.stopChan:
				log.Println("ServerManager: Stopped.")
				return
			}
		}
	}()
}

// StartAsync is like Start but performs the initial server probe in the
// background, returning immediately. This avoids blocking the caller for
// testTimeout * numServers when the upstream is slow or unreachable.
// GetBestServer() may return "" until the first probe completes; callers
// should fall back to the first configured server in that case.
func (sm *ServerManager) StartAsync() {
	log.Println("ServerManager: Starting (async)...")
	go func() {
		sm.testServers()

		ticker := time.NewTicker(sm.testInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				sm.testServers()
			case <-sm.stopChan:
				log.Println("ServerManager: Stopped.")
				return
			}
		}
	}()
}

// Stop terminates the background testing goroutine.
func (sm *ServerManager) Stop() {
	sm.stopOnce.Do(func() {
		close(sm.stopChan)
	})
}

// GetBestServer returns the current active server.
func (sm *ServerManager) GetBestServer() string {
	if sm == nil {
		return ""
	}
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.activeServer
}

// HasWorkingServer returns true if an active server is set.
func (sm *ServerManager) HasWorkingServer() bool {
	if sm == nil {
		return false
	}
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.activeServer != ""
}

// GetServers returns the current list of servers.
func (sm *ServerManager) GetServers() []string {
	if sm == nil {
		return nil
	}
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	servers := make([]string, len(sm.servers))
	copy(servers, sm.servers)
	return servers
}

// UpdateServers safely replaces the current server list and triggers new tests.
func (sm *ServerManager) UpdateServers(newServers []string) {
	if sm == nil {
		return
	}
	sm.mu.Lock()
	sm.servers = newServers
	sm.mu.Unlock()
	log.Printf("ServerManager: Server list updated with %d servers.", len(newServers))
	go sm.testServers()
}

// ReportFailure is called when an upstream dial fails. 
// It clears the active server if it matches and triggers a re-test.
func (sm *ServerManager) ReportFailure(addr string) {
	sm.mu.Lock()
	if sm.activeServer == addr {
		log.Printf("ServerManager: Passive check failed for %s, clearing active server", addr)
		sm.activeServer = ""
		sm.lastSuccess = time.Time{} // Reset success timer
		go sm.testServers()
	}
	sm.mu.Unlock()
}

// ReportSuccess is called when an upstream connection is successfully used.
// This allows skipping active tests if the server is known to be healthy.
func (sm *ServerManager) ReportSuccess(addr string) {
	sm.mu.Lock()
	if sm.activeServer == addr {
		sm.lastSuccess = time.Now()
	}
	sm.mu.Unlock()
}

// SetSelfPorts sets the local ports listened by vproxy to prevent self-loop.
func (sm *ServerManager) SetSelfPorts(ports []int) {
	if sm == nil {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.selfPorts = ports
}

// IsSelfUpstream checks if an upstream address points to vproxy itself.
func (sm *ServerManager) IsSelfUpstream(addr string) bool {
	if sm == nil {
		return false
	}
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if len(sm.selfPorts) == 0 {
		return false
	}
	u, err := url.Parse(addr)
	if err != nil {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	isLoopback := host == "localhost" || (ip != nil && ip.IsLoopback())
	if !isLoopback {
		return false
	}
	portStr := u.Port()
	if portStr == "" {
		switch u.Scheme {
		case "http":
			portStr = "80"
		case "socks5":
			portStr = "1080"
		case "tproxy":
			portStr = "10080"
		}
	}
	port, _ := strconv.Atoi(portStr)
	for _, sp := range sm.selfPorts {
		if sp > 0 && sp == port {
			return true
		}
	}
	return false
}

// testServers performs a simple TCP port check on servers in order.
func (sm *ServerManager) testServers() {
	sm.mu.RLock()
	active := sm.activeServer
	last := sm.lastSuccess
	servers := make([]string, len(sm.servers))
	copy(servers, sm.servers)
	sm.mu.RUnlock()

	// If we have an active server and it was successfully used recently, 
	// skip the active probe to save resources (passive check reuse).
	if active != "" && time.Since(last) < sm.testInterval {
		return
	}

	var foundAddr string

	if len(servers) == 0 {
		return
	}

	for _, addr := range servers {
		if sm.IsSelfUpstream(addr) {
			log.Printf("ServerManager: Upstream %s points to self listening port, skipping to prevent loop", addr)
			continue
		}
		dialAddr := addr
		scheme := ""
		if u, err := url.Parse(addr); err == nil && u.Host != "" {
			dialAddr = u.Host
			scheme = u.Scheme
			if !strings.Contains(dialAddr, ":") {
				switch u.Scheme {
				case "http":
					dialAddr += ":80"
				case "https":
					dialAddr += ":443"
				case "socks5":
					dialAddr += ":1080"
				case "tproxy":
					dialAddr += ":10080"
				}
			}
		}

		dialer := &net.Dialer{
			Timeout: sm.testTimeout,
			Control: GetDialerControl(),
		}
		conn, err := dialer.DialContext(context.Background(), "tcp", dialAddr)
		if err == nil {
			// If it's a SOCKS5 server, do a simple handshake to ensure it's actually a proxy
			// and not just a random open port (like our own vproxy bridge which hasn't finished starting)
			if scheme == "socks5" {
				conn.SetDeadline(time.Now().Add(sm.testTimeout))
				// SOCKS5 handshake: [0x05, 0x01, 0x00] (Version 5, 1 method, No Auth)
				_, err = conn.Write([]byte{0x05, 0x01, 0x00})
				if err == nil {
					resp := make([]byte, 2)
					_, err = io.ReadFull(conn, resp)
					if err == nil && resp[0] == 0x05 {
						// Success!
					} else {
						err = fmt.Errorf("invalid SOCKS5 response")
					}
				}
			}

			conn.Close()
			if err == nil {
				foundAddr = addr
				break
			}
		}
	}

	sm.mu.Lock()
	if foundAddr != "" {
		if sm.activeServer != foundAddr {
			sm.activeServer = foundAddr
			log.Printf("ServerManager: Active server set to %s", sm.activeServer)
		}
	} else {
		if len(servers) > 0 {
			Errorf("All %d upstream servers are unreachable", len(servers))
		}
		if sm.activeServer != "" {
			log.Println("ServerManager: Clearing active server")
			sm.activeServer = ""
		}
	}
	sm.mu.Unlock()
}
