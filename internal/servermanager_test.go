package internal

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestServerManager_Priority(t *testing.T) {
	// Create two test servers
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s1.Close()

	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// s2 is faster but s1 should be picked in priority mode
		w.WriteHeader(http.StatusOK)
	}))
	defer s2.Close()

	sm := NewServerManager([]string{s1.URL, s2.URL}, 1*time.Minute, 1*time.Second)

	sm.testServers()

	best := sm.GetBestServer()
	if best != s1.URL {
		t.Errorf("Expected active server to be %s (first in list), got %s", s1.URL, best)
	}

	// Now swap the order
	sm2 := NewServerManager([]string{s2.URL, s1.URL}, 1*time.Minute, 1*time.Second)
	sm2.testServers()

	best2 := sm2.GetBestServer()
	if best2 != s2.URL {
		t.Errorf("Expected active server to be %s (first in list), got %s", s2.URL, best2)
	}
}

func TestServerManager_FirstFailed(t *testing.T) {
    // s1 is broken, s2 is working
    s1 := "http://127.0.0.1:1" // Invalid port
    
	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s2.Close()

	sm := NewServerManager([]string{s1, s2.URL}, 1*time.Minute, 1*time.Second)

	sm.testServers()

	best := sm.GetBestServer()
	if best != s2.URL {
		t.Errorf("Expected active server to be %s (first working), got %s", s2.URL, best)
	}
}

func TestServerManager_TProxy(t *testing.T) {
	// Create a test tproxy server (which is a TCP listener)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String() // "127.0.0.1:port"
	tproxyURL := "tproxy://" + addr

	sm := NewServerManager([]string{tproxyURL}, 1*time.Minute, 1*time.Second)
	sm.testServers()

	best := sm.GetBestServer()
	if best != tproxyURL {
		t.Errorf("Expected active server to be %s, got %s", tproxyURL, best)
	}
}
