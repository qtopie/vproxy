package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/qtopie/vproxy/proxy/ebpf"
	"github.com/qtopie/vproxy/proxy/tproxy"
	"github.com/qtopie/vproxy/socks"
)
func main() {
	upstream := "192.168.50.31:1080"
	tproxyPort := 10080

	// Phase 2: Check for CAP_NET_ADMIN and enable marking
	if err := ebpf.CheckPermission(); err != nil {
		log.Printf("Warning: cannot set SO_MARK (missing CAP_NET_ADMIN): %v", err)
		log.Printf("Bypass will not work. You might need: sudo setcap cap_net_admin+ep bin/test_tproxy")
	} else {
		ebpf.SetEnabled(true)
		fmt.Println("eBPF SO_MARK bypass enabled (0xff)")
	}

	fmt.Printf("Starting TProxy test listener on :%d\n", tproxyPort)
	// ...

	fmt.Printf("Forwarding to SOCKS5 upstream: %s\n", upstream)

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tproxyPort))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConn(conn, upstream)
		}
	}()

	fmt.Println("TProxy ready. To test, run in another terminal:")
	fmt.Printf("sudo iptables -t nat -A OUTPUT -p tcp -d 1.1.1.1 -j REDIRECT --to-ports %d\n", tproxyPort)
	fmt.Println("curl -v 1.1.1.1")
	fmt.Println("\nPress Ctrl+C to stop.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func handleConn(conn net.Conn, upstream string) {
	defer conn.Close()

	target, err := tproxy.GetOriginalDst(conn)
	if err != nil {
		fmt.Printf("Error getting original dst: %v\n", err)
		return
	}

	fmt.Printf("TProxy: %s -> %s\n", conn.RemoteAddr(), target)

	// Use custom Socks5Proxy with Dialer Control for SO_MARK bypass
	p := socks.NewSocks5Proxy(upstream, "", "")
	rc, err := p.DialTCP(context.Background(), target, 5*time.Second, ebpf.GetDialerControl())
	if err != nil {
		fmt.Printf("Failed to dial upstream: %v\n", err)
		return
	}
	defer rc.Close()

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(rc, conn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, rc)
		errCh <- err
	}()

	<-errCh
}
