package socks

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestManualUDPAssociate(t *testing.T) {
	if os.Getenv("MANUAL_TEST") == "" {
		t.Skip("Skipping manual SOCKS5 UDP test. Set MANUAL_TEST=1 to run.")
	}

	proxyAddr := "127.0.0.1:1080"
	// 准备一个 DNS 查询包 (Query for google.com A record)
	dnsQuery := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags: Standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // Terminator
		0x00, 0x01, // Type: A
		0x00, 0x01, // Class: IN
	}

	// 1. 发起 TCP 控制连接
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Failed to connect to proxy TCP: %v", err)
	}
	defer conn.Close()

	// SOCKS5 Greeting: [VER, NMETHODS, METHODS]
	conn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 1024)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		t.Fatal(err)
	}

	// SOCKS5 UDP Associate Request: [VER, CMD, RSV, ATYP, ADDR, PORT]
	// 请求 UDP Associate，客户端不限制自己的源地址 (0.0.0.0:0)
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(req)

	// Read Reply Header (VER, REP, RSV)
	if _, err := io.ReadFull(conn, buf[:3]); err != nil {
		t.Fatal(err)
	}
	if buf[1] != 0x00 {
		t.Fatalf("SOCKS5 UDP Associate failed with rep: %d", buf[1])
	}

	// Read BND.ADDR (starts with ATYP) and BND.PORT
	bndAddr, err := readAddr(conn, buf)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("UDP Associate successful. Relay address: %s\n", bndAddr.String())

	// 2. 发送 UDP 数据包
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	relayUDPAddr, err := net.ResolveUDPAddr("udp", bndAddr.String())
	if err != nil {
		t.Fatal(err)
	}

	// 构造 SOCKS5 UDP 封装: [RSV(2), FRAG(1), ATYP, DST.ADDR, DST.PORT, DATA]
	target := ParseAddr("8.8.8.8:53")
	packet := append([]byte{0x00, 0x00, 0x00}, target...)
	packet = append(packet, dnsQuery...)

	_, err = udpConn.WriteToUDP(packet, relayUDPAddr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Sent UDP packet to relay %v, target 8.8.8.8:53\n", relayUDPAddr)

	// 3. 接收响应
	udpConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, remoteAddr, err := udpConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("Failed to receive UDP response: %v", err)
	}

	fmt.Printf("Received UDP response from %v, length %d\n", remoteAddr, n)
	if n < 10 {
		t.Fatal("Response too short")
	}

	// 解析 SOCKS5 UDP 响应头
	respAddr := SplitAddr(buf[3:n])
	fmt.Printf("SOCKS5 UDP Response Source: %s\n", respAddr.String())
	payload := buf[3+len(respAddr) : n]
	if len(payload) > 0 && bytes.Contains(payload, []byte("google")) {
		fmt.Println("SUCCESS: Received valid DNS response!")
		fmt.Println(string(payload))
	} else {
		t.Errorf("Response payload does not seem to contain DNS answer for google.com")
	}
}

// minimal SOCKS5 server used by tests: performs greeting, accepts method 0,
// accepts CONNECT and replies success. It does not actually connect to target;
// it simply returns success so client-side handshake succeeds.
func runTestSocksServer(t *testing.T) (addr string, stop func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	stopped := make(chan struct{})
	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stopped:
					return
				default:
					t.Logf("accept error: %v", err)
					return
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				// perform minimal server-side SOCKS5: greeting + CONNECT parse
				h := make([]byte, 2)
				if _, err := io.ReadFull(c, h); err != nil {
					return
				}
				nmethods := int(h[1])
				if nmethods > 0 {
					methods := make([]byte, nmethods)
					if _, err := io.ReadFull(c, methods); err != nil {
						return
					}
				}
				// reply: no auth
				if _, err := c.Write([]byte{5, 0}); err != nil {
					return
				}

				// read request header
				hdr := make([]byte, 4)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				atyp := hdr[3]
				// read dst addr and port according to atyp
				switch atyp {
				case 1:
					// IPv4: 4 bytes addr + 2 bytes port
					buf := make([]byte, 6)
					if _, err := io.ReadFull(c, buf); err != nil {
						return
					}
				case 3:
					// domain: 1 byte len + len + 2 bytes port
					var lbuf [1]byte
					if _, err := io.ReadFull(c, lbuf[:]); err != nil {
						return
					}
					blen := int(lbuf[0])
					if blen > 0 {
						if _, err := io.ReadFull(c, make([]byte, blen)); err != nil {
							return
						}
					}
					if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
						return
					}
				case 4:
					// IPv6: 16 bytes addr + 2 bytes port
					if _, err := io.ReadFull(c, make([]byte, 18)); err != nil {
						return
					}
				default:
					return
				}

				// send success reply: VER, REP=0, RSV, ATYP=1 + BND.ADDR(4) + BND.PORT(2)
				if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				// keep connection open a bit
				time.Sleep(500 * time.Millisecond)
			}(conn)
		}
	}()

	return ln.Addr().String(), func() { close(stopped) }
}

// NOTE: ClientConnect behavior is exercised indirectly via DialSocks5 test.

func TestDialSocks5(t *testing.T) {
	addr, stop := runTestSocksServer(t)
	defer stop()

	// DialSocks5 should contact the socks server and perform handshake; the
	// returned connection is the proxied connection (server in our test returns
	// success immediately).
	c, err := DialSocks5(addr, "example.com:80")
	if err != nil {
		t.Fatalf("DialSocks5 failed: %v", err)
	}
	defer c.Close()
}


