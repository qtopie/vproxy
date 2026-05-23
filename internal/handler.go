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

	"bytes"
	"crypto/tls"
	"io"
	"sync"
	"sync/atomic"

	"github.com/qtopie/vproxy/internal/mitm"
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
	socksLn     net.Listener
	httpLn      net.Listener
	transLn     net.Listener
	transUDPLn  *net.UDPConn
	udpSessions sync.Map
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
		log.Printf("Transparent proxy port %d is already in use, binding to a free port instead...", ph.TransPort)
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
	}
	ph.transLn = ln
	ph.TransPort = ln.Addr().(*net.TCPAddr).Port
	go ph.serveTransparent()

	udpLn, err := tproxy.ListenUDPTransparent(ph.TransPort)
	if err != nil {
		log.Printf("Failed to listen transparent UDP on %d: %v", ph.TransPort, err)
	} else {
		ph.transUDPLn = udpLn
		go ph.serveTransparentUDP()
	}

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
	if ph.transUDPLn != nil {
		ph.transUDPLn.Close()
		ph.transUDPLn = nil
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

func (ph *ProxyHandler) serveTransparentUDP() {
	buf := make([]byte, 65535)
	oob := make([]byte, 1024)
	for {
		n, src, dst, err := tproxy.ReadFromUDPWithOrigDst(ph.transUDPLn, buf, oob)
		if err != nil {
			return
		}
		if dst == nil {
			continue // ignore packets without orig dst
		}

		sessionKey := src.String() + "|" + dst.String()
		session, loaded := ph.udpSessions.Load(sessionKey)
		var upstream net.Conn
		if !loaded {
			Infof("[UDP] Intercepted new UDP session from %s targeting %s", src.String(), dst.String())
			upstream, err = ph.dialTargetUDP(dst.String())
			if err != nil {
				Errorf("[UDP] Failed to dial upstream UDP for %s: %v", dst.String(), err)
				continue
			}

			spoofConn, err := tproxy.DialUDPTransparent(dst)
			if err != nil {
				Errorf("[UDP] Failed to create spoofing UDP socket for %s: %v", dst.String(), err)
				upstream.Close()
				continue
			}

			ph.udpSessions.Store(sessionKey, upstream)

			go func(srcAddr *net.UDPAddr, up net.Conn, spoof *net.UDPConn, key string) {
				defer up.Close()
				defer spoof.Close()
				defer ph.udpSessions.Delete(key)

				relayBuf := make([]byte, 65535)
				for {
					up.SetReadDeadline(time.Now().Add(5 * time.Minute))
					rn, rerr := up.Read(relayBuf)
					if rerr != nil {
						return
					}
					Debugf("[UDP] Relayed %d bytes from %s to client %s", rn, dst.String(), srcAddr.String())
					spoof.WriteToUDP(relayBuf[:rn], srcAddr)
				}
			}(src, upstream, spoofConn, sessionKey)

			session = upstream
		} else {
			upstream = session.(net.Conn)
		}

		Debugf("[UDP] Relayed %d bytes from client %s to %s", n, src.String(), dst.String())
		upstream.Write(buf[:n])
	}
}

type peekedConn struct {
	*bufio.Reader
	net.Conn
}

func (c *peekedConn) Read(p []byte) (n int, err error) {
	return c.Reader.Read(p)
}

var traceCounter uint64

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

			// only support CONNECT method for MITM
			if req.Method != http.MethodConnect {
				res := http.Response{StatusCode: http.StatusMethodNotAllowed, ProtoMajor: 1, ProtoMinor: 1}
				res.Write(conn)
				return
			}

			// Deep HTTPS Tracing (MITM) when verbose/debug mode is enabled
			if IsVerbose() {
				// Establish TLS connection with the target server
				serverTLS, err := ph.dialTargetTLS(req.Host)
				if err != nil {
					log.Printf("MITM: failed to dial target TLS %s: %v", req.Host, err)
					res := http.Response{StatusCode: http.StatusBadGateway, ProtoMajor: 1, ProtoMinor: 1}
					res.Write(conn)
					return
				}

				// Respond 200 OK to the client
				_, err = fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
				if err != nil {
					serverTLS.Close()
					return
				}

				// Get dynamic cert for the host signed by our Root CA
				leafCert, err := mitm.GetCertificateForHost(req.Host)
				if err != nil {
					log.Printf("MITM: failed to generate cert for %s: %v", req.Host, err)
					serverTLS.Close()
					return
				}

				clientBuffered := &peekedConn{Reader: reader, Conn: conn}
				clientTLS := tls.Server(clientBuffered, &tls.Config{
					Certificates: []tls.Certificate{leafCert},
					NextProtos:   []string{"http/1.1"}, // Force HTTP/1.1 to simplify parsing
				})

				// Handle deep HTTP tracing
				ph.handlePlainHTTP(clientTLS, serverTLS, req.Host)
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

func (ph *ProxyHandler) handlePlainHTTP(client, server net.Conn, host string) {
	defer client.Close()
	defer server.Close()

	clientReader := bufio.NewReader(client)
	serverReader := bufio.NewReader(server)

	// Try reading the first request
	req, err := http.ReadRequest(clientReader)
	if err != nil {
		// Fallback to relaying raw bytes
		bufferedBytes, _ := clientReader.Peek(clientReader.Buffered())
		if len(bufferedBytes) > 0 {
			server.Write(bufferedBytes)
		}
		Relay(context.Background(), server, client)
		return
	}

	for {
		startTime := time.Now()

		var reqBodyBytes []byte
		if req.Body != nil {
			reqBodyBytes, _ = io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewBuffer(reqBodyBytes))
		}

		err = req.Write(server)
		if err != nil {
			log.Printf("MITM: Failed to write request to server: %v", err)
			return
		}

		resp, err := http.ReadResponse(serverReader, req)
		if err != nil {
			log.Printf("MITM: Failed to read response from server: %v", err)
			return
		}

		latency := time.Since(startTime)

		var respBodyBytes []byte
		if resp.Body != nil {
			respBodyBytes, _ = io.ReadAll(resp.Body)
			resp.Body = io.NopCloser(bytes.NewBuffer(respBodyBytes))
		}

		// Populate and publish structured TraceEntry
		traceID := fmt.Sprintf("trace-%04d", atomic.AddUint64(&traceCounter, 1))
		entry := TraceEntry{
			ID:           traceID,
			Timestamp:    startTime,
			Method:       req.Method,
			URL:          req.URL.String(),
			Path:         req.URL.Path,
			Host:         host,
			RequestProto: req.Proto,
			ReqHeaders:   req.Header,
			ReqBody:      ProcessBody(reqBodyBytes),
			StatusCode:   resp.StatusCode,
			RespHeaders:  resp.Header,
			RespBody:     ProcessBody(respBodyBytes),
			LatencyMs:    float64(latency.Nanoseconds()) / 1e6, // convert ns to ms
		}
		PublishTrace(&entry)

		err = resp.Write(client)
		if err != nil {
			return
		}

		// Read next request
		req, err = http.ReadRequest(clientReader)
		if err != nil {
			return
		}
	}
}

func (ph *ProxyHandler) dialTargetTLS(target string) (*tls.Conn, error) {
	conn, err := ph.dialTarget(target)
	if err != nil {
		return nil, err
	}

	host, _, _ := net.SplitHostPort(target)
	insecure := false
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		insecure = true
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: insecure,
		NextProtos:         []string{"http/1.1"},
	})

	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func (ph *ProxyHandler) dialTarget(target string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(target)
	if ph.rm.Match(host) == ActionDirect {
		return dialDirect(target)
	}

	upstreamURL := ph.sm.GetBestServer()
	if upstreamURL == "" {
		servers := ph.sm.GetServers()
		if len(servers) > 0 {
			upstreamURL = servers[0]
		} else {
			return nil, fmt.Errorf("no upstream servers configured")
		}
	}

	u, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, err
	}

	var rc net.Conn
	switch u.Scheme {
	case "socks5":
		rc, err = socks.DialSocks5(u.Host, target)
	case "http":
		rc, err = dialHTTP(u.Host, target)
	default:
		return nil, fmt.Errorf("unsupported upstream scheme: %s", u.Scheme)
	}

	if err != nil {
		ph.sm.ReportFailure(upstreamURL)
		return nil, err
	}
	ph.sm.ReportSuccess(upstreamURL)
	return rc, nil
}

func (ph *ProxyHandler) dialTargetUDP(target string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(target)
	if ph.rm.Match(host) == ActionDirect {
		// Just dial directly for UDP bypassing proxy
		d := net.Dialer{
			Timeout: 5 * time.Second,
			Control: ebpf.GetDialerControl(),
		}
		return d.Dial("udp", target)
	}

	upstreamURL := ph.sm.GetBestServer()
	if upstreamURL == "" {
		servers := ph.sm.GetServers()
		if len(servers) > 0 {
			upstreamURL = servers[0]
		} else {
			return nil, fmt.Errorf("no upstream servers configured")
		}
	}

	u, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, err
	}

	var rc net.Conn
	switch u.Scheme {
	case "socks5":
		p := socks.NewSocks5Proxy(u.Host, "", "")
		rc, err = p.DialUDP(context.Background(), target, 5*time.Second, ebpf.GetDialerControl())
	default:
		return nil, fmt.Errorf("unsupported upstream scheme for UDP: %s", u.Scheme)
	}

	if err != nil {
		ph.sm.ReportFailure(upstreamURL)
		return nil, err
	}
	ph.sm.ReportSuccess(upstreamURL)
	return rc, nil
}

func (ph *ProxyHandler) forward(conn net.Conn, target string) {
	traceID := fmt.Sprintf("conn-%04d", atomic.AddUint64(&traceCounter, 1))
	ctx := context.WithValue(context.Background(), traceKey{}, traceID)
	ctx = context.WithValue(ctx, startTimeKey{}, time.Now())

	TraceInfof(ctx, "Accepted connection from %s targeting %s", conn.RemoteAddr(), target)

	rc, err := ph.dialTarget(target)
	if err != nil {
		TraceErrorf(ctx, "Failed to connect to target %s: %v", target, err)
		return
	}
	defer rc.Close()

	TraceInfof(ctx, "Successfully established tunnel to target %s", target)
	err = Relay(ctx, rc, conn)
	if err != nil {
		TraceErrorf(ctx, "Tunnel closed with error: %v", err)
	} else {
		TraceInfof(ctx, "Tunnel closed cleanly")
	}
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
