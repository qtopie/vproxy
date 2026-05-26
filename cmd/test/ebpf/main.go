package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/qtopie/vproxy/proxy/cgroup"
	"github.com/qtopie/vproxy/proxy/ebpf"
)

func main() {
	fmt.Println("=== Test 4: eBPF Interception ===")
	
	// 1. Setup Cgroup
	if err := cgroup.EnsureVProxyCgroup(); err != nil {
		fmt.Printf("❌ Failed to ensure cgroup: %v\n", err)
		os.Exit(1)
	}
	if err := cgroup.MoveProcessToVProxyCgroup(os.Getpid()); err != nil {
		fmt.Printf("❌ Failed to move to cgroup: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ Moved to vproxy cgroup")

	// 2. Load eBPF
	r, err := ebpf.Load("/sys/fs/cgroup/vproxy", 12345, 0xff, false, nil, 0)
	if err != nil {
		fmt.Printf("❌ Failed to load eBPF: %v\n", err)
		os.Exit(1)
	}
	defer r.Unload()
	fmt.Println("✅ Loaded eBPF programs")

	// 3. Start listener
	ln, err := net.Listen("tcp", "127.0.0.1:12345")
	if err != nil {
		fmt.Printf("❌ Failed to bind listener: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()

	go func() {
		fmt.Println("Listener waiting for connection...")
		conn, err := ln.Accept()
		if err == nil {
			fmt.Printf("✅ Listener intercepted connection from: %s\n", conn.RemoteAddr())
			conn.Close()
		} else {
			fmt.Printf("❌ Listener accept failed: %v\n", err)
		}
	}()

	// 4. Dial
	time.Sleep(100 * time.Millisecond) // Wait for listener
	fmt.Println("Dialing 1.1.1.1:80...")
	conn, err := net.DialTimeout("tcp", "1.1.1.1:80", 2*time.Second)
	if err != nil {
		fmt.Printf("❌ Dial failed: %v\n", err)
	} else {
		fmt.Printf("✅ Dial succeeded to: %s\n", conn.RemoteAddr())
		conn.Close()
	}
	
	time.Sleep(1 * time.Second)
	fmt.Println("Test finished.")
}
