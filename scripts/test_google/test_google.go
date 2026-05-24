package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	fmt.Println("Attempting to fetch google.com via transparent proxy...")
	resp, err := http.Get("https://www.google.com")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 100))
	fmt.Printf("Success! Status: %s\n", resp.Status)
	fmt.Printf("Start of body: %s...\n", string(body))
}
