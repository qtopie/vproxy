package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	testURL := os.Getenv("TEST_URL")
	if testURL == "" {
		testURL = "https://www.google.com"
	}

	testProto := strings.ToLower(os.Getenv("TEST_PROTO")) // "ipv4" or "ipv6"

	fmt.Printf("=================== Google Connection Test ===================\n")
	fmt.Printf("Target URL:      %s\n", testURL)
	if testProto != "" {
		fmt.Printf("Forced Proto:    %s\n", testProto)
	}
	fmt.Printf("==============================================================\n")

	// Create custom dialer to trace DNS and TCP connection details
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			// DNS lookup trace
			fmt.Printf("[DNS] Looking up: %s\n", host)
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				fmt.Printf("[DNS] Error resolving %s: %v\n", host, err)
				return nil, err
			}

			var targetIP net.IP
			for _, ip := range ips {
				isIPv4 := ip.To4() != nil
				if testProto == "ipv4" && isIPv4 {
					targetIP = ip
					break
				}
				if testProto == "ipv6" && !isIPv4 {
					targetIP = ip
					break
				}
				if testProto == "" {
					targetIP = ip
					break
				}
			}

			if targetIP == nil {
				return nil, fmt.Errorf("no suitable IP found for %s (forced: %s)", host, testProto)
			}

			fmt.Printf("[DNS] Resolved: %s -> %s\n", host, targetIP.String())

			dialNetwork := "tcp"
			if testProto == "ipv4" {
				dialNetwork = "tcp4"
			} else if testProto == "ipv6" {
				dialNetwork = "tcp6"
			}

			targetAddr := net.JoinHostPort(targetIP.String(), port)
			fmt.Printf("[TCP] Dialing %s using %s...\n", targetAddr, dialNetwork)

			conn, err := dialer.DialContext(ctx, dialNetwork, targetAddr)
			if err != nil {
				fmt.Printf("[TCP] Dial failed: %v\n", err)
				return nil, err
			}

			fmt.Printf("[TCP] Connected! Local: %s -> Remote: %s\n", conn.LocalAddr(), conn.RemoteAddr())
			return conn, nil
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		fmt.Printf("[HTTP] Failed to create request: %v\n", err)
		os.Exit(1)
	}

	// Make request
	fmt.Printf("[HTTP] Executing GET request...\n")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[HTTP] Request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	fmt.Printf("[HTTP] Response Status: %s\n", resp.Status)
	fmt.Printf("[HTTP] Protocol:        %s\n", resp.Proto)

	body, err := io.ReadAll(io.LimitReader(resp.Body, 200))
	if err != nil {
		fmt.Printf("[HTTP] Failed to read body: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[HTTP] Body Preview (up to 200 bytes):\n%s\n", string(body))
	fmt.Printf("==============================================================\n")
	fmt.Println("Success!")
}

