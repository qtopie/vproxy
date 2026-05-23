package internal

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/qtopie/vproxy/proxy/ebpf"
	"github.com/qtopie/vproxy/proxy/tproxy"
	"github.com/qtopie/vproxy/socks"
)

type ProxyHandler struct {
	sm        *ServerManager
	rm        *RuleManager
	SocksPort int
	HttpPort  int
	TransPort int
	socksLn   net.Listener
	httpLn    net.Listener
	transLn   net.Listener
}

// NewProxyHandler constructs a ProxyHandler. Exported to allow callers in other packages
// to create the handler without accessing internal fields directly.
func NewProxyHandler(sm *ServerManager, rm *RuleManager, socksPort, httpPort, transPort int) *ProxyHandler {
	return &ProxyHandler{
		sm:        sm,
		rm:        rm,
		SocksPort: socksPort,
		HttpPort:  httpPort,
		TransPort: transPort,
	}
}

// UpdateServers updates the upstream server list used by the handler's server manager.
func (ph *ProxyHandler) UpdateServers(upstreams []string) {
	if ph.sm != nil {
		ph.sm.UpdateServers(upstreams)
	}
}

// UpdateRules replaces the rule manager with a new one built from the rules string.
func (ph *ProxyHandler) UpdateRules(rules []string) {
	ph.rm = NewRuleManager(rules)
}

func (ph *ProxyHandler) StartSocks() error {
	if ph.socksLn != nil {
		return nil
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ph.SocksPort))
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
	}
	ph.socksLn = ln
	ph.SocksPort = ln.Addr().(*net.TCPAddr).Port
	go ph.serveSocks()
	return nil
}

func (ph *ProxyHandler) StartHTTP() error {
	if ph.httpLn != nil {
		return nil
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ph.HttpPort))
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
	}
	ph.httpLn = ln
	ph.HttpPort = ln.Addr().(*net.TCPAddr).Port
	go ph.serveHTTP()
	return nil
}

func (ph *ProxyHandler) StartTransparent() error {
	if ph.transLn != nil {
		return nil
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ph.TransPort))
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
	}
	ph.transLn = ln
	ph.TransPort = ln.Addr().(*net.TCPAddr).Port
	go ph.serveTransparent()
	return nil
}

func (ph *ProxyHandler) Stop() {
	if ph.socksLn != nil {
		ph.socksLn.Close()
		ph.socksLn = nil
	}
	if ph.httpLn != nil {
		ph.httpLn.Close()
		ph.httpLn = nil
	}
	if ph.transLn != nil {
		ph.transLn.Close()
		ph.transLn = nil
	}
}

func (ph *ProxyHandler) serveSocks() {
	for {
		conn, err := ph.socksLn.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			tgt, _, err := socks.Handshake(conn)
			if err != nil {
				return
			}
			ph.forward(conn, tgt.String())
		}(conn)
	}
}

func (ph *ProxyHandler) serveTransparent() {
	for {
		conn, err := ph.transLn.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			target, err := tproxy.GetOriginalDst(conn)
			if err != nil {
				log.Printf("Failed to get original destination: %v", err)
				return
			}
			ph.forward(conn, target)
		}(conn)
	}
}

type peekedConn struct {
	*bufio.Reader
	net.Conn
}

func (c *peekedConn) Read(p []byte) (n int, err error) {
	return c.Reader.Read(p)
}

func (ph *ProxyHandler) serveHTTP() {
	for {
		conn, err := ph.httpLn.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()

			reader := bufio.NewReader(conn)
			req, err := http.ReadRequest(reader)
			if err != nil {
				return
			}

			// only support CONNECT method
			if req.Method != http.MethodConnect {
				res := http.Response{StatusCode: http.StatusMethodNotAllowed, ProtoMajor: 1, ProtoMinor: 1}
				res.Write(conn)
				return
			}

			// 3. 向客户端回送 HTTP 200 Connection Established
			_, err = fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			if err != nil {
				return
			}

			clientBuffered := &peekedConn{Reader: reader, Conn: conn}
			ph.forward(clientBuffered, req.Host)
		}(conn)
	}
}

func (ph *ProxyHandler) forward(conn net.Conn, target string) {
	host, _, _ := net.SplitHostPort(target)
	if ph.rm.Match(host) == ActionDirect {
		// direct connection
		rc, err := dialDirect(target)
		if err != nil {
			return
		}
		defer rc.Close()
		Relay(context.Background(), rc, conn)
		return
	}

	upstreamURL := ph.sm.GetBestServer()
	if upstreamURL == "" {
		servers := ph.sm.GetServers()
		if len(servers) > 0 {
			upstreamURL = servers[0]
		} else {
			return
		}
	}

	u, err := url.Parse(upstreamURL)
	if err != nil {
		return
	}

	var rc net.Conn
	switch u.Scheme {
	case "socks5":
		rc, err = socks.DialSocks5(u.Host, target)
	case "http":
		rc, err = dialHTTP(u.Host, target)
	default:
		return
	}

	if err != nil {
		log.Printf("Dial upstream failed: %v", err)
		ph.sm.ReportFailure(upstreamURL)
		return
	}
	defer rc.Close()
	ph.sm.ReportSuccess(upstreamURL)

	Relay(context.Background(), rc, conn)
}

// (Socks dialing is provided by the socks package.)
func dialHTTP(proxyAddr, target string) (net.Conn, error) {
	d := net.Dialer{
		Timeout: 5 * time.Second,
		Control: ebpf.GetDialerControl(),
	}
	conn, err := d.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("HTTP proxy error: %s", resp.Status)
	}
	return conn, nil
}

func dialDirect(target string) (net.Conn, error) {
	d := net.Dialer{
		Timeout: 5 * time.Second,
		Control: ebpf.GetDialerControl(),
	}
	return d.Dial("tcp", target)
}
