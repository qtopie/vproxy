package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	fmt.Println("=== Test 1: Direct Network Connectivity ===")
	transport := &http.Transport{
		Proxy: nil, // explicitly disable environment proxies
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", "https://cn.bing.com/", nil)
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

	_, err = io.ReadAll(io.LimitReader(resp.Body, 100))
	if err != nil {
		fmt.Printf("❌ Failed to read body: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Success! Status: %s\n", resp.Status)
}
