package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

func main() {
	fmt.Println("=== Test 2: Upstream Proxy Connectivity ===")
	proxyStr := "socks5://127.0.0.1:1080"
	if len(os.Args) > 1 {
		proxyStr = os.Args[1]
	}
	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		fmt.Printf("❌ Invalid proxy URL: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Testing via proxy: %s\n", proxyURL.String())
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	req, err := http.NewRequest("GET", "https://www.google.cn/", nil)
	if err != nil {
		fmt.Printf("❌ Failed to create request: %v\n", err)
		os.Exit(1)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("❌ Request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 100))
	if err != nil {
		fmt.Printf("❌ Failed to read body: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Success! Status: %s\n", resp.Status)
	fmt.Printf("Response snippet: %s\n", string(body))
}
