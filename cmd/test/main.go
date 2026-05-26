package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	fmt.Println("Starting network test (ignoring env proxies)...")
	// Custom transport that ignores environment proxies
	transport := &http.Transport{
		Proxy: nil, // explicitly set to nil
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	req, err := http.NewRequest("GET", "https://google.com", nil)
	if err != nil {
		fmt.Printf("Failed to create request: %v\n", err)
		os.Exit(1)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 100))
	if err != nil {
		fmt.Printf("Failed to read body: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Success! Status: %s\n", resp.Status)
	fmt.Printf("Response snippet: %s\n", string(body))
}
