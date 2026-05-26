package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	fmt.Println("=== Test: HTTPS Google Connectivity ===")
	
	// Standard client with system cert pool (vproxy will inject CA)
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	url := "https://www.google.com"
	fmt.Printf("Requesting %s...\n", url)

	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("❌ Request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	fmt.Printf("✅ Status: %s\n", resp.Status)

	body, err := io.ReadAll(io.LimitReader(resp.Body, 100))
	if err != nil {
		fmt.Printf("❌ Failed to read response body: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Response snippet: %s...\n", string(body))
	fmt.Println("Test finished.")
}
