package internal

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"bytes"
	"crypto/tls"
	"io"
	"mime"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/qtopie/vproxy/internal/dns"
	"github.com/qtopie/vproxy/internal/mitm"
	"github.com/qtopie/vproxy/proxy/ebpf"
	"github.com/qtopie/vproxy/proxy/tproxy"
	"github.com/qtopie/vproxy/socks"
)

type ProxyHandler struct {
	sm             *ServerManager
	rm             *RuleManager
	SocksPort      int
	HttpPort       int
	TransPort      int
	DialTimeout    time.Duration
	DialRetryCount int
	socksLn        net.Listener
	httpLn         net.Listener
	transLn        net.Listener
	transUDPLn     *net.UDPConn
	udpSessions    sync.Map
	ebpfResult     *ebpf.LoadResult
}

// SetEbpfResult sets the eBPF load result containing maps for orig dst lookup.
func (ph *ProxyHandler) SetEbpfResult(r *ebpf.LoadResult) {
	ph.ebpfResult = r
}

// NewProxyHandler constructs a ProxyHandler. Exported to allow callers in other packages
// to create the handler without accessing internal fields directly.
func NewProxyHandler(sm *ServerManager, rm *RuleManager, socksPort, httpPort, transPort int) *ProxyHandler {
	return &ProxyHandler{
		sm:             sm,
		rm:             rm,
		SocksPort:      socksPort,
		HttpPort:       httpPort,
		TransPort:      transPort,
		DialTimeout:    5000 * time.Millisecond, // Default 5 seconds
		DialRetryCount: 3,                       // Default 3 attempts
	}
}

// UpdateServers updates the upstream server list used by the handler's server manager.
func (ph *ProxyHandler) UpdateServers(upstreams []string) {
	if ph.sm != nil {
		ph.sm.UpdateServers(upstreams)
	}
}

// UpdateRules replaces the rule manager with a new one built from the rules string.
func (ph *ProxyHandler) UpdateRules(rules []string, directDNS bool) {
	ph.rm = NewRuleManager(rules)
	ph.rm.SetDirectDNS(directDNS)
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

	if runtime.GOOS == "darwin" {
		SetDialerControl(tproxy.GetDialerControl())
		go func() {
			err := tproxy.StartDarwinTransparent(context.Background(), func(conn net.Conn) {
				defer conn.Close()
				target, err := tproxy.GetOriginalDst(conn)
				if err != nil {
					log.Printf("Failed to get original destination: %v", err)
					return
				}
				ph.forward(conn, target)
			}, ph.handleUDP)
			if err != nil {
				log.Printf("Failed to start macOS transparent proxy: %v", err)
			}
		}()
		return nil
	}

	if runtime.GOOS == "windows" {
		SetDialerControl(tproxy.GetDialerControl())
		go func() {
			err := tproxy.StartWindowsTransparent(context.Background(), func(conn net.Conn) {
				defer conn.Close()
				target, err := tproxy.GetOriginalDst(conn)
				if err != nil {
					log.Printf("Failed to get original destination: %v", err)
					return
				}
				ph.forward(conn, target)
			}, ph.handleUDP)
			if err != nil {
				log.Printf("Failed to start Windows transparent proxy: %v", err)
			}
		}()
		return nil
	}

	if runtime.GOOS == "linux" && os.Getenv("VP_USE_TUN") == "1" {
		SetDialerControl(tproxy.GetDialerControl())
		go func() {
			err := tproxy.StartLinuxTransparent(context.Background(), func(conn net.Conn) {
				defer conn.Close()
				target, err := tproxy.GetOriginalDst(conn)
				if err != nil {
					log.Printf("Failed to get original destination: %v", err)
					return
				}
				ph.forward(conn, target)
			}, ph.handleUDP)
			if err != nil {
				log.Printf("Failed to start Linux TUN transparent proxy: %v", err)
			}
		}()
		return nil
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", ph.TransPort))
	if err != nil {
		Infof("Transparent proxy port %d is already in use, binding to a free port instead...", ph.TransPort)
		ln, err = net.Listen("tcp", ":0")
		if err != nil {
			return err
		}
	}
	ph.transLn = ln
	ph.TransPort = ln.Addr().(*net.TCPAddr).Port
	Infof("Transparent TCP proxy listening on %d (mode: redirect)", ph.TransPort)
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

func (ph *ProxyHandler) handleUDP(ctx context.Context, local net.Conn, target string) {
	// Restore domain from Fake-IP if necessary
	if dns.GlobalPool != nil {
		host, port, err := net.SplitHostPort(target)
		if err == nil {
			ip := net.ParseIP(host)
			if ip != nil && dns.GlobalPool.IsFakeIP(ip) {
				domain := dns.GlobalPool.GetDomain(ip)
				if domain != "" {
					target = net.JoinHostPort(domain, port)
					log.Printf("[TUN] Restored UDP Fake-IP %s -> %s", host, domain)
				}
			}
		}
	}

	defer local.Close()
	process := ""
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		process, _ = tproxy.GetProcessNameByConn(local)
	}
	upstream, err := ph.dialTargetUDP(target, process)
	if err != nil {
		Errorf("[UDP] Failed to dial upstream for %s: %v", target, err)
		return
	}
	defer upstream.Close()

	done := make(chan struct{})
	go func() {
		io.Copy(upstream, local)
		close(done)
	}()
	io.Copy(local, upstream)
	<-done
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

			traceID := fmt.Sprintf("conn-%04d", atomic.AddUint64(&traceCounter, 1))
			ctx := context.WithValue(context.Background(), traceKey{}, traceID)
			ctx = context.WithValue(ctx, startTimeKey{}, time.Now())
			TraceInfof(ctx, "[SOCKS5] Accepted connection from %s targeting %s", conn.RemoteAddr(), tgt.String())

			rc, err := ph.dialTarget(tgt.String(), "")
			if err != nil {
				TraceErrorf(ctx, "[SOCKS5] Failed to connect to target %s: %v", tgt.String(), err)
				socks.WriteReply(conn, socks.ErrConnectionRefused, nil)
				return
			}
			defer rc.Close()

			if err := socks.WriteReply(conn, socks.Error(0), nil); err != nil {
				TraceErrorf(ctx, "[SOCKS5] Failed to write handshake reply: %v", err)
				return
			}

			TraceInfof(ctx, "[SOCKS5] Successfully established tunnel to target %s", tgt.String())
			err = Relay(ctx, rc, conn)
			if err != nil {
				TraceErrorf(ctx, "[SOCKS5] Tunnel closed with error: %v", err)
			} else {
				TraceInfof(ctx, "[SOCKS5] Tunnel closed cleanly")
			}
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
			var target string
			var err error
			if ph.ebpfResult != nil && ph.ebpfResult.TCPOrigDst != nil {
				if origAddr, errLookup := ebpf.LookupTCPOrigDst(ph.ebpfResult.TCPOrigDst, conn); errLookup == nil {
					target = origAddr.String()
					Debugf("[Transparent] Resolved original DST from eBPF map: %s", target)
				} else {
					target, err = tproxy.GetOriginalDst(conn)
					if err == nil {
						Debugf("[Transparent] Resolved original DST from SO_ORIGINAL_DST: %s", target)
					}
				}
			} else {
				target, err = tproxy.GetOriginalDst(conn)
				if err == nil {
					Debugf("[Transparent] Resolved original DST from SO_ORIGINAL_DST: %s", target)
				}
			}
			if err != nil {
				log.Printf("[Transparent] Failed to get original destination from %s: %v", conn.RemoteAddr(), err)
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
		if ph.ebpfResult != nil && ph.ebpfResult.UDPOrigDst != nil {
			if origDst, errLookup := ebpf.LookupUDPOrigDst(ph.ebpfResult.UDPOrigDst, src); errLookup == nil {
				dst = origDst
			}
		}
		if dst == nil {
			continue // ignore packets without orig dst
		}

		sessionKey := src.String() + "|" + dst.String()
		session, loaded := ph.udpSessions.Load(sessionKey)
		var upstream net.Conn
		if !loaded {
			process := ""
			if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
				process, _ = tproxy.GetProcessNameByPort(src.Port)
			}
			Infof("[UDP] Intercepted new UDP session from %s (Process: %s) targeting %s", src.String(), process, dst.String())
			upstream, err = ph.dialTargetUDP(dst.String(), process)
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

			process := ""
			if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
				process, _ = tproxy.GetProcessNameByConn(conn)
			}

			// Check if we should intercept this connection (MITM)
			hostOnly := req.Host
			if h, _, err := net.SplitHostPort(req.Host); err == nil {
				hostOnly = h
			}
			action, _ := ph.rm.MatchContext(MatchContext{Host: hostOnly, Process: process})

			// Deep HTTPS Tracing (MITM) when verbose mode is on OR explicitly intercepted/mapped
			if IsVerbose() || action == ActionIntercept || action == ActionMap {
				// Establish TLS connection with the target server
				serverTLS, err := ph.dialTargetTLS(req.Host, process)
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

		// 1. Whistle-like Mapping: Check if this specific URL should be hijacked
		fullURL := fmt.Sprintf("https://%s%s", host, req.URL.RequestURI())
		action, target := ph.rm.MatchURL(fullURL)
		if action == ActionMap && strings.HasPrefix(target, "file://") {
			localPath := strings.TrimPrefix(target, "file://")
			ph.serveLocalFile(client, localPath)

			// Record trace for the hijacked request
			traceID := fmt.Sprintf("map-%04d", atomic.AddUint64(&traceCounter, 1))
			PublishTrace(&TraceEntry{
				ID:           traceID,
				Timestamp:    startTime,
				Method:       req.Method,
				URL:          fullURL,
				Path:         req.URL.Path,
				Host:         host,
				RequestProto: req.Proto,
				StatusCode:   200,
				RespHeaders:  http.Header{"X-VProxy-Map": []string{localPath}},
				RespBody:     fmt.Sprintf("[Mapped to Local File: %s]", localPath),
				LatencyMs:    float64(time.Since(startTime).Nanoseconds()) / 1e6,
			})

			// Wait for next request on the same connection
			req, err = http.ReadRequest(clientReader)
			if err != nil {
				return
			}
			continue
		}

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
			URL:          fullURL,
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

func (ph *ProxyHandler) serveLocalFile(conn net.Conn, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("MAP: failed to read local file %s: %v", path, err)
		res := http.Response{
			StatusCode: 404,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString("Local file not found by vproxy")),
		}
		res.Header.Set("Content-Type", "text/plain")
		res.Write(conn)
		return
	}

	contentType := mime.TypeByExtension(filepath.Ext(path))
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	header := make(http.Header)
	header.Set("Content-Type", contentType)
	header.Set("Content-Length", strconv.Itoa(len(data)))
	header.Set("Access-Control-Allow-Origin", "*")
	header.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE, PATCH")
	header.Set("Access-Control-Allow-Headers", "*")
	header.Set("Server", "vproxy-mitm")

	res := http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header,
		Body:       io.NopCloser(bytes.NewBuffer(data)),
	}
	res.Write(conn)
}

func (ph *ProxyHandler) dialTargetTLS(target string, process string) (*tls.Conn, error) {
	conn, err := ph.dialTarget(target, process)
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

func (ph *ProxyHandler) dialTarget(target string, process string) (net.Conn, error) {
	host, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	action, _ := ph.rm.MatchContext(MatchContext{Host: host, Port: port, Process: process})
	if action == ActionDirect {
		Debugf("[Dial] Target %s matches DIRECT rule, dialing directly", target)
		return ph.dialDirect(target)
	}

	retryCount := ph.DialRetryCount
	if retryCount <= 0 {
		retryCount = 3
	}
	dialTimeout := ph.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}

	var rc net.Conn
	var lastErr error

	for attempt := 1; attempt <= retryCount; attempt++ {
		upstreamURL := ph.sm.GetBestServer()
		if upstreamURL == "" {
			servers := ph.sm.GetServers()
			if len(servers) > 0 {
				upstreamURL = servers[0]
				Debugf("[Dial] No verified upstream, falling back to first configured: %s (attempt %d/%d)", upstreamURL, attempt, retryCount)
			} else {
				return nil, fmt.Errorf("no upstream servers configured")
			}
		} else {
			Debugf("[Dial] Routing %s through upstream: %s (attempt %d/%d)", target, upstreamURL, attempt, retryCount)
		}

		u, err := url.Parse(upstreamURL)
		if err != nil {
			return nil, err
		}

		switch u.Scheme {
		case "socks5":
			p := socks.NewSocks5Proxy(u.Host, "", "")
			rc, err = p.DialTCP(context.Background(), target, dialTimeout, GetDialerControl())
		case "http":
			rc, err = dialHTTPWithTimeout(u.Host, target, dialTimeout)
		default:
			return nil, fmt.Errorf("unsupported upstream scheme: %s", u.Scheme)
		}

		if err == nil {
			ph.sm.ReportSuccess(upstreamURL)
			return rc, nil
		}

		Debugf("[Dial] Attempt %d/%d to %s failed: %v", attempt, retryCount, upstreamURL, err)
		ph.sm.ReportFailure(upstreamURL)
		lastErr = err

		if attempt < retryCount {
			time.Sleep(100 * time.Millisecond)
		}
	}

	return nil, fmt.Errorf("all TCP dial attempts failed, last error: %w", lastErr)
}

func (ph *ProxyHandler) dialTargetUDP(target string, process string) (net.Conn, error) {
	host, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	
	dialTimeout := ph.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}
	dialRetryCount := ph.DialRetryCount
	if dialRetryCount <= 0 {
		dialRetryCount = 3
	}

	action, _ := ph.rm.MatchContext(MatchContext{Host: host, Port: port, Process: process})
	if action == ActionDirect {
		// Just dial directly for UDP bypassing proxy

		d := net.Dialer{
			Timeout: dialTimeout,
			Control: GetDialerControl(),
		}
		return d.Dial("udp", target)
	}

	var rc net.Conn
	var lastErr error

	for attempt := 1; attempt <= dialRetryCount; attempt++ {
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

		switch u.Scheme {
		case "socks5":
			p := socks.NewSocks5Proxy(u.Host, "", "")
			rc, err = p.DialUDP(context.Background(), target, dialTimeout, GetDialerControl())
		default:
			return nil, fmt.Errorf("unsupported upstream scheme for UDP: %s", u.Scheme)
		}

		if err == nil {
			ph.sm.ReportSuccess(upstreamURL)
			return rc, nil
		}

		Debugf("[Dial UDP] Attempt %d/%d to %s failed: %v", attempt, dialRetryCount, upstreamURL, err)
		ph.sm.ReportFailure(upstreamURL)
		lastErr = err

		if attempt < dialRetryCount {
			time.Sleep(100 * time.Millisecond)
		}
	}

	return nil, fmt.Errorf("all UDP dial attempts failed, last error: %w", lastErr)
}

func (ph *ProxyHandler) forward(conn net.Conn, target string) {
	// Restore domain from Fake-IP if necessary
	if dns.GlobalPool != nil {
		host, port, err := net.SplitHostPort(target)
		if err == nil {
			ip := net.ParseIP(host)
			if ip != nil && dns.GlobalPool.IsFakeIP(ip) {
				domain := dns.GlobalPool.GetDomain(ip)
				if domain != "" {
					target = net.JoinHostPort(domain, port)
					log.Printf("[TUN] Restored Fake-IP %s -> %s", host, domain)
				}
			}
		}
	}

	process := ""
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		process, _ = tproxy.GetProcessNameByConn(conn)
	}

	traceID := fmt.Sprintf("conn-%04d", atomic.AddUint64(&traceCounter, 1))
	ctx := context.WithValue(context.Background(), traceKey{}, traceID)
	ctx = context.WithValue(ctx, startTimeKey{}, time.Now())

	if process != "" {
		TraceInfof(ctx, "Accepted connection from %s (Process: %s) targeting %s", conn.RemoteAddr(), process, target)
	} else {
		TraceInfof(ctx, "Accepted connection from %s targeting %s", conn.RemoteAddr(), target)
	}

	// Loop detection: prevent vproxy from connecting to itself.
	// For TUN/GVisor, target == LocalAddr is expected behavior, so we only check this for REDIRECT/eBPF modes.
	if target == conn.LocalAddr().String() && !tproxy.IsTUNConn(conn) {
		TraceErrorf(ctx, "Loop detected: target is the same as local address %s, dropping connection", target)
		return
	}

	rc, err := ph.dialTarget(target, process)
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
func dialHTTPWithTimeout(proxyAddr, target string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{
		Timeout: timeout,
		Control: GetDialerControl(),
	}
	conn, err := d.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	
	// Set read/write deadline for HTTP CONNECT handshake
	conn.SetDeadline(time.Now().Add(timeout))
	
	// Create a buffered reader to read the response headers
	br := bufio.NewReader(conn)
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("HTTP proxy error: %s", resp.Status)
	}
	
	// Reset the deadline so normal connection operations are not timed out!
	conn.SetDeadline(time.Time{})
	
	// Return a wrapped connection that includes any data already read into the buffer
	Debugf("[Dial] Established HTTP CONNECT tunnel to %s via %s (buffered: %d bytes)", target, proxyAddr, br.Buffered())
	return &peekedConn{Reader: br, Conn: conn}, nil
}

func (ph *ProxyHandler) dialDirect(target string) (net.Conn, error) {
	retryCount := ph.DialRetryCount
	if retryCount <= 0 {
		retryCount = 3
	}
	dialTimeout := ph.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}

	var rc net.Conn
	var lastErr error
	for attempt := 1; attempt <= retryCount; attempt++ {
		d := net.Dialer{
			Timeout: dialTimeout,
			Control: GetDialerControl(),
		}
		rc, lastErr = d.Dial("tcp", target)
		if lastErr == nil {
			return rc, nil
		}
		Debugf("[Dial] Direct dial attempt %d/%d to %s failed: %v", attempt, retryCount, target, lastErr)
		if attempt < retryCount {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return nil, lastErr
}
