package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const maxSnippet = 256

func main() {
	proxyURL := flag.String("proxy", "socks5://127.0.0.1:1080", "SOCKS5 proxy URL")
	targetURL := flag.String("target", "https://www.google.com/", "URL to request through the proxy")
	timeout := flag.Duration("timeout", 15*time.Second, "timeout for each network operation")
	flag.Parse()

	if err := run(*proxyURL, *targetURL, *timeout); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: SOCKS5 proxy request completed")
}

func run(proxyURL, targetURL string, timeout time.Duration) error {
	if timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}

	parsedProxy, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("parse proxy URL: %w", err)
	}
	if parsedProxy.Scheme != "socks5" && parsedProxy.Scheme != "socks5h" {
		return fmt.Errorf("unsupported proxy scheme %q; use socks5:// or socks5h://", parsedProxy.Scheme)
	}
	if parsedProxy.Host == "" {
		return fmt.Errorf("proxy URL has no host")
	}

	parsedTarget, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("parse target URL: %w", err)
	}
	if parsedTarget.Scheme != "http" && parsedTarget.Scheme != "https" {
		return fmt.Errorf("unsupported target scheme %q; use http:// or https://", parsedTarget.Scheme)
	}
	if parsedTarget.Host == "" {
		return fmt.Errorf("target URL has no host")
	}
	targetAddress := parsedTarget.Host
	if _, _, err := net.SplitHostPort(targetAddress); err != nil {
		port := "80"
		if parsedTarget.Scheme == "https" {
			port = "443"
		}
		targetAddress = net.JoinHostPort(parsedTarget.Hostname(), port)
	}

	fmt.Printf("Proxy:  %s\nTarget: %s\nTimeout: %s\n", proxyURL, targetURL, timeout)

	tcpStart := time.Now()
	conn, err := net.DialTimeout("tcp", parsedProxy.Host, timeout)
	if err != nil {
		return fmt.Errorf("SOCKS5 endpoint TCP connect failed after %s: %w", time.Since(tcpStart).Round(time.Millisecond), err)
	}
	_ = conn.Close()
	fmt.Printf("TCP endpoint: PASS (%s)\n", time.Since(tcpStart).Round(time.Millisecond))

	dialer, err := proxy.SOCKS5("tcp", parsedProxy.Host, nil, &net.Dialer{Timeout: timeout})
	if err != nil {
		return fmt.Errorf("create SOCKS5 dialer: %w", err)
	}

	connectStart := time.Now()
	targetConn, err := dialer.Dial("tcp", targetAddress)
	if err != nil {
		return fmt.Errorf("SOCKS5 CONNECT failed after %s: %w", time.Since(connectStart).Round(time.Millisecond), err)
	}
	_ = targetConn.Close()
	fmt.Printf("SOCKS5 CONNECT: PASS (%s)\n", time.Since(connectStart).Round(time.Millisecond))

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.Dial(network, address)
		},
	}
	client := &http.Client{Transport: transport, Timeout: timeout}
	defer transport.CloseIdleConnections()

	requestStart := time.Now()
	resp, err := client.Get(targetURL)
	if err != nil {
		return fmt.Errorf("HTTP request failed after %s: %w", time.Since(requestStart).Round(time.Millisecond), err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSnippet))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	snippet := strings.Join(strings.Fields(string(body)), " ")
	fmt.Printf("HTTP request: %s (%s)\n", resp.Status, time.Since(requestStart).Round(time.Millisecond))
	fmt.Printf("Response snippet: %q\n", snippet)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("target returned non-success status %s", resp.Status)
	}
	return nil
}
