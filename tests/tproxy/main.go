package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/qtopie/vproxy/proxy/tproxy"
)

func main() {
	fmt.Println("=== Test 5: SO_ORIGINAL_DST Extraction ===")
	
	ln, err := net.Listen("tcp", "127.0.0.1:12345")
	if err != nil {
		fmt.Printf("❌ Failed to bind listener: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			target, err := tproxy.GetOriginalDst(conn)
			if err != nil {
				fmt.Printf("❌ Failed to get original destination: %v\n", err)
			} else {
				fmt.Printf("✅ Extracted original destination: %s\n", target)
			}
			conn.Close()
		}
	}()

	fmt.Println("Setting up temporary iptables REDIRECT rule (via expect)...")
	runWithSudoExpect("iptables -t nat -A OUTPUT -p tcp -d 1.1.1.1 -j REDIRECT --to-ports 12345")
	defer func() {
		fmt.Println("Cleaning up iptables rule (via expect)...")
		runWithSudoExpect("iptables -t nat -D OUTPUT -p tcp -d 1.1.1.1 -j REDIRECT --to-ports 12345")
	}()

	fmt.Println("Dialing 1.1.1.1:80...")
	conn, err := net.DialTimeout("tcp", "1.1.1.1:80", 2*time.Second)
	if err == nil {
		conn.Close()
	}
	
	time.Sleep(500 * time.Millisecond)
	fmt.Println("Test finished.")
}

func runWithSudoExpect(cmdStr string) {
	if os.Geteuid() == 0 {
		exec.Command("sh", "-c", cmdStr).Run()
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("❌ Failed to get home dir: %v\n", err)
		return
	}
	passFile := home + "/.pass"
	passBytes, err := os.ReadFile(passFile)
	if err != nil {
		fmt.Printf("❌ Failed to read pass file: %v\n", err)
		return
	}
	pass := string(passBytes)
	// trim trailing newline
	if len(pass) > 0 && pass[len(pass)-1] == '\n' {
		pass = pass[:len(pass)-1]
	}

	expectScript := fmt.Sprintf(`
set timeout 10
spawn sudo %s
expect {
    "*Password:*" {
        send "%s\r"
        exp_continue
    }
    eof
}
`, cmdStr, pass)

	exec.Command("expect", "-c", expectScript).Run()
}
