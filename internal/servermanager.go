package internal

import (
	"context"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ServerManager holds a list of servers, periodically tests them, and provides the best one.
type ServerManager struct {
	servers      []string
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
		dialAddr := addr
		if u, err := url.Parse(addr); err == nil && u.Host != "" {
			dialAddr = u.Host
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
			conn.Close()
			foundAddr = addr
			break
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
