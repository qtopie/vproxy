package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

func main() {
	fmt.Println("\033[1;36m==================================================\033[0m")
	fmt.Println("\033[1;36m=== Test Suite: HTTPS Google Connection Test ===\033[0m")
	fmt.Println("\033[1;36m==================================================\033[0m")

	// Read environment flags
	testProto := strings.ToLower(os.Getenv("TEST_PROTO"))
	if testProto == "" {
		testProto = "ipv4"
	}
	testMode := strings.ToLower(os.Getenv("TEST_MODE"))
	if testMode == "" {
		testMode = "transparent"
	}
	testIntercept := strings.ToLower(os.Getenv("TEST_INTERCEPT"))

	fmt.Printf("\033[1;33m[*] Configurations Detected:\033[0m\n")
	fmt.Printf("    - Protocol Flag  (TEST_PROTO):      %s\n", testProto)
	fmt.Printf("    - Proxy Mode     (TEST_MODE):       %s\n", testMode)
	if testIntercept != "" {
		fmt.Printf("    - Interceptor    (TEST_INTERCEPT):  %s\n", testIntercept)
	}

	// 1. Validate Interception Mode on Linux if transparent
	if runtime.GOOS == "linux" && testMode == "transparent" && testIntercept != "" {
		forceIptables := os.Getenv("VP_FORCE_IPTABLES") == "1"
		if testIntercept == "iptables" {
			if !forceIptables {
				fmt.Println("\033[1;31m❌ Verification Failed: Expected 'iptables' mode, but VP_FORCE_IPTABLES is not set to '1'!\033[0m")
				os.Exit(1)
			}
			fmt.Println("    - \033[1;32m✓ Verified: Interception correctly forced to iptables (VP_FORCE_IPTABLES=1)\033[0m")
		} else if testIntercept == "ebpf" {
			if forceIptables {
				fmt.Println("\033[1;31m❌ Verification Failed: Expected 'ebpf' mode, but VP_FORCE_IPTABLES is set to '1'!\033[0m")
				os.Exit(1)
			}
			fmt.Println("    - \033[1;32m✓ Verified: Interception mode defaults to eBPF (VP_FORCE_IPTABLES is off)\033[0m")
		}
	}

	// 2. Select Target URL based on Protocol
	targetURL := os.Getenv("TEST_URL")
	if targetURL == "" {
		if testProto == "ipv6" {
			targetURL = "https://ipv6.google.com"
		} else {
			targetURL = "https://www.google.com"
		}
	}
	fmt.Printf("    - Target URL:                       %s\n\n", targetURL)

	// 3. Build Dialer
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// Apply SOCKS5 Proxy settings if SOCKS5 mode is enabled
	if testMode == "socks5" {
		socksAddr := os.Getenv("SOCKS5_PROXY")
		if socksAddr == "" {
			socksAddr = "127.0.0.1:1080"
		}
		
		dialerSOCKS, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
		if err != nil {
			fmt.Printf("\033[1;31m❌ Failed to create SOCKS5 dialer: %v\033[0m\n", err)
			os.Exit(1)
		}

		if contextDialer, ok := dialerSOCKS.(proxy.ContextDialer); ok {
			transport.DialContext = contextDialer.DialContext
		} else {
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialerSOCKS.Dial(network, addr)
			}
		}
		fmt.Printf("\033[1;33m[*] Routing traffic via SOCKS5 proxy: %s\033[0m\n", socksAddr)
	} else {
		// Apply Custom DialContext to restrict network families in transparent mode if requested
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if testProto == "ipv4" {
				network = "tcp4"
			} else if testProto == "ipv6" {
				network = "tcp6"
			}
			return dialer.DialContext(ctx, network, addr)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	// 4. Fire Request
	fmt.Printf("\033[1;36m[*] Requesting %s ...\033[0m\n", targetURL)
	start := time.Now()
	resp, err := client.Get(targetURL)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("\033[1;31m❌ Connection Test Failed: %v\033[0m\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	fmt.Printf("\033[1;32m✅ Connection Test Succeeded! [RTT: %v]\033[0m\n", duration)
	fmt.Printf("    - Status Code: %s\n", resp.Status)

	body, err := io.ReadAll(io.LimitReader(resp.Body, 100))
	if err != nil {
		fmt.Printf("\033[1;31m❌ Failed to read response body: %v\033[0m\n", err)
		os.Exit(1)
	}

	snippet := strings.ReplaceAll(string(body), "\n", " ")
	fmt.Printf("    - Content Snippet: %s...\n", snippet)
	fmt.Println("\033[1;36m==================================================\033[0m")
}
