// Package socks implements essential parts of SOCKS protocol.
package socks

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/qtopie/vproxy/proxy/ebpf"
	proxypkg "golang.org/x/net/proxy"
)

// DefaultDialerControl specifies the default dialer control function to use when bypassing transparent proxy redirection.
var DefaultDialerControl func(network, address string, c syscall.RawConn) error


// SOCKS request commands as defined in RFC 1928 section 4.
const (
	Version5        = 0x05 // SOCKS5 protocol version
	CmdConnect      = 1
	CmdBind         = 2
	CmdUDPAssociate = 3
)

// SOCKS address types as defined in RFC 1928 section 5.
const (
	AtypIPv4       = 1
	AtypDomainName = 3
	AtypIPv6       = 4
)

// Error represents a SOCKS error
type Error byte

func (err Error) Error() string {
	return "SOCKS error: " + strconv.Itoa(int(err))
}

// SOCKS errors as defined in RFC 1928 section 6.
const (
	ErrGeneralFailure       = Error(1)
	ErrConnectionNotAllowed = Error(2)
	ErrNetworkUnreachable   = Error(3)
	ErrHostUnreachable      = Error(4)
	ErrConnectionRefused    = Error(5)
	ErrTTLExpired           = Error(6)
	ErrCommandNotSupported  = Error(7)
	ErrAddressNotSupported  = Error(8)
	InfoUDPAssociate        = Error(9)
)

// MaxAddrLen is the maximum size of SOCKS address in bytes.
const MaxAddrLen = 1 + 1 + 255 + 2

// Addr represents a SOCKS address as defined in RFC 1928 section 5.
type Addr []byte

// String serializes SOCKS address a to string form.
func (a Addr) String() string {
	var host, port string

	switch a[0] { // address type
	case AtypDomainName:
		host = string(a[2 : 2+int(a[1])])
		port = strconv.Itoa((int(a[2+int(a[1])]) << 8) | int(a[2+int(a[1])+1]))
	case AtypIPv4:
		host = net.IP(a[1 : 1+net.IPv4len]).String()
		port = strconv.Itoa((int(a[1+net.IPv4len]) << 8) | int(a[1+net.IPv4len+1]))
	case AtypIPv6:
		host = net.IP(a[1 : 1+net.IPv6len]).String()
		port = strconv.Itoa((int(a[1+net.IPv6len]) << 8) | int(a[1+net.IPv6len+1]))
	}

	return net.JoinHostPort(host, port)
}

func readAddr(r io.Reader, b []byte) (Addr, error) {
	if len(b) < MaxAddrLen {
		return nil, io.ErrShortBuffer
	}
	_, err := io.ReadFull(r, b[:1]) // read 1st byte for address type
	if err != nil {
		return nil, err
	}

	switch b[0] {
	case AtypDomainName:
		_, err = io.ReadFull(r, b[1:2]) // read 2nd byte for domain length
		if err != nil {
			return nil, err
		}
		_, err = io.ReadFull(r, b[2:2+int(b[1])+2])
		return b[:1+1+int(b[1])+2], err
	case AtypIPv4:
		_, err = io.ReadFull(r, b[1:1+net.IPv4len+2])
		return b[:1+net.IPv4len+2], err
	case AtypIPv6:
		_, err = io.ReadFull(r, b[1:1+net.IPv6len+2])
		return b[:1+net.IPv6len+2], err
	}

	return nil, ErrAddressNotSupported
}

// ReadAddr reads just enough bytes from r to get a valid Addr.
func ReadAddr(r io.Reader) (Addr, error) {
	return readAddr(r, make([]byte, MaxAddrLen))
}

// DialSocks5 dials the given target through a SOCKS5 proxy at proxyAddr.
// It applies the same ebpf control (SO_MARK) used elsewhere to avoid redirect loops.
func DialSocks5(proxyAddr, target string) (net.Conn, error) {
	p := NewSocks5Proxy(proxyAddr, "", "")
	return p.DialTCP(context.Background(), target, 5*time.Second, DefaultDialerControl)
}

// SplitAddr slices a SOCKS address from beginning of b. Returns nil if failed.
func SplitAddr(b []byte) Addr {
	addrLen := 1
	if len(b) < addrLen {
		return nil
	}

	switch b[0] {
	case AtypDomainName:
		if len(b) < 2 {
			return nil
		}
		addrLen = 1 + 1 + int(b[1]) + 2
	case AtypIPv4:
		addrLen = 1 + net.IPv4len + 2
	case AtypIPv6:
		addrLen = 1 + net.IPv6len + 2
	default:
		return nil

	}

	if len(b) < addrLen {
		return nil
	}

	return b[:addrLen]
}

// ParseAddr parses the address in string s. Returns nil if failed.
func ParseAddr(s string) Addr {
	var addr Addr
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addr = make([]byte, 1+net.IPv4len+2)
			addr[0] = AtypIPv4
			copy(addr[1:], ip4)
		} else {
			addr = make([]byte, 1+net.IPv6len+2)
			addr[0] = AtypIPv6
			copy(addr[1:], ip)
		}
	} else {
		if len(host) > 255 {
			return nil
		}
		addr = make([]byte, 1+1+len(host)+2)
		addr[0] = AtypDomainName
		addr[1] = byte(len(host))
		copy(addr[2:], host)
	}

	portnum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil
	}

	addr[len(addr)-2], addr[len(addr)-1] = byte(portnum>>8), byte(portnum)

	return addr
}

// Handshake fast-tracks SOCKS initialization to get target address and command.
func Handshake(rw io.ReadWriter) (Addr, byte, error) {
	// Read RFC 1928 for request and reply structure and sizes.
	buf := make([]byte, MaxAddrLen)
	// read VER, NMETHODS, METHODS
	if _, err := io.ReadFull(rw, buf[:2]); err != nil {
		return nil, 0, fmt.Errorf("failed to read VER and NMETHODS: %w", err)
	}
	nmethods := buf[1]
	if _, err := io.ReadFull(rw, buf[:nmethods]); err != nil {
		return nil, 0, fmt.Errorf("failed to read METHODS: %w", err)
	}
	// write VER METHOD
	if _, err := rw.Write([]byte{Version5, 0}); err != nil {
		return nil, 0, fmt.Errorf("failed to write greeting response: %w", err)
	}
	// read VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err := io.ReadFull(rw, buf[:3]); err != nil {
		return nil, 0, fmt.Errorf("failed to read request header: %w", err)
	}
	cmd := buf[1]
	addr, err := readAddr(rw, buf)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read target address: %w", err)
	}

	return addr, cmd, nil
}

// WriteReply writes a SOCKS5 reply to w.
func WriteReply(w io.Writer, rep Error, addr Addr) error {
	if addr == nil {
		addr = []byte{AtypIPv4, 0, 0, 0, 0, 0, 0}
	}
	_, err := w.Write(append([]byte{Version5, byte(rep), 0}, addr...))
	return err
}

// ControlDialer wraps a control function to implement proxy.Dialer
type ControlDialer struct {
	Context context.Context
	Timeout time.Duration
	Control func(network, address string, c syscall.RawConn) error
}

func (d *ControlDialer) Dial(network, address string) (net.Conn, error) {
	control := d.Control
	if control == nil {
		control = DefaultDialerControl
	}
	if control == nil {
		control = ebpf.GetDialerControl()
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	nd := &net.Dialer{
		Timeout: timeout,
		Control: control,
	}
	if host, _, err := net.SplitHostPort(address); err == nil {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			nd.Control = nil
		}
	}
	ctx := d.Context
	if ctx == nil {
		ctx = context.Background()
	}
	
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	
	conn, err := nd.DialContext(dialCtx, network, address)
	if err != nil {
		return nil, err
	}
	
	// Set an initial deadline for SOCKS5 handshake/negotiation.
	// This will be cleared by the caller (DialTCP or DialUDP) once the handshake finishes.
	conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

// Socks5Proxy implements an upstream SOCKS5 proxy with both TCP dialer and a
// simple UDP ASSOC handler.
type Socks5Proxy struct {
	Addr string
	User string
	Pass string
}

func NewSocks5Proxy(addr, user, pass string) *Socks5Proxy {
	return &Socks5Proxy{Addr: addr, User: user, Pass: pass}
}

// DialTCP dials a TCP connection to targetAddr via upstream SOCKS5.
// control is an optional function to apply to the underlying TCP connection to the SOCKS server.
func (s *Socks5Proxy) DialTCP(ctx context.Context, targetAddr string, timeout time.Duration, control func(network, address string, c syscall.RawConn) error) (net.Conn, error) {
	var auth *proxypkg.Auth
	if s.User != "" {
		auth = &proxypkg.Auth{User: s.User, Password: s.Pass}
	}

	d := &ControlDialer{
		Context: ctx,
		Timeout: timeout,
		Control: control,
	}
	dialer, err := proxypkg.SOCKS5("tcp", s.Addr, auth, d)
	if err != nil {
		return nil, err
	}
	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return nil, err
	}
	// Handshake successful, reset connection deadline so normal data transmission isn't cut off!
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// DialUDP implements SOCKS5 UDP ASSOCIATE.
func (s *Socks5Proxy) DialUDP(ctx context.Context, targetAddr string, timeout time.Duration, control func(network, address string, c syscall.RawConn) error) (net.Conn, error) {
	// 1. 建立 TCP 控制连接
	d := &ControlDialer{
		Context: ctx,
		Timeout: timeout,
		Control: control,
	}
	ctrlConn, err := d.Dial("tcp", s.Addr)
	if err != nil {
		return nil, fmt.Errorf("udp associate: failed to connect to socks server: %w", err)
	}

	// 2. SOCKS5 认证与 UDP ASSOCIATE 请求
	// 简单的无认证握手
	if _, err := ctrlConn.Write([]byte{Version5, 1, 0}); err != nil {
		ctrlConn.Close()
		return nil, err
	}
	buf := make([]byte, MaxAddrLen)
	if _, err := io.ReadFull(ctrlConn, buf[:2]); err != nil {
		ctrlConn.Close()
		return nil, err
	}
	
	// 发送 UDP ASSOCIATE 请求 (地址设为 0.0.0.0:0)
	req := []byte{Version5, CmdUDPAssociate, 0, AtypIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := ctrlConn.Write(req); err != nil {
		ctrlConn.Close()
		return nil, err
	}

	// 读取服务器返回的 BND.ADDR 和 BND.PORT
	if _, err := io.ReadFull(ctrlConn, buf[:3]); err != nil {
		ctrlConn.Close()
		return nil, err
	}
	relayAddr, err := readAddr(ctrlConn, buf)
	if err != nil {
		ctrlConn.Close()
		return nil, err
	}

	// 3. 创建本地 UDP Socket 准备与服务器的转发地址通信
	if control == nil {
		control = DefaultDialerControl
	}
	if control == nil {
		control = ebpf.GetDialerControl()
	}
	nd := &net.Dialer{
		Timeout: timeout,
		Control: control,
	}
	udpConn, err := nd.DialContext(ctx, "udp", relayAddr.String())
	if err != nil {
		ctrlConn.Close()
		return nil, fmt.Errorf("udp associate: failed to dial relay: %w", err)
	}

	target := ParseAddr(targetAddr)
	if target == nil {
		ctrlConn.Close()
		udpConn.Close()
		return nil, fmt.Errorf("invalid target address: %s", targetAddr)
	}

	// Handshake successful, reset ctrlConn deadline so the associate TCP control connection doesn't timeout!
	ctrlConn.SetDeadline(time.Time{})

	return &socksUDPConn{
		UDPConn:  udpConn.(*net.UDPConn),
		ctrlConn: ctrlConn,
		target:   target,
	}, nil
}

// socksUDPConn wraps a UDP connection with SOCKS5 encapsulation.
type socksUDPConn struct {
	*net.UDPConn
	ctrlConn net.Conn
	target   Addr
}

func (c *socksUDPConn) Write(b []byte) (int, error) {
	// 封装头部: [RSV(2)|FRAG(1)|ATYP(1)|DST.ADDR|DST.PORT|DATA]
	// 1. 准备 RSV(2) + FRAG(1) = 3 字节零
	header := []byte{0, 0, 0}
	// 2. 拼接目标地址和原始数据
	payload := append(header, c.target...)
	payload = append(payload, b...)
	
	_, err := c.UDPConn.Write(payload)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *socksUDPConn) Read(b []byte) (int, error) {
	buf := make([]byte, 65535)
	n, err := c.UDPConn.Read(buf)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	
	// 简单的头部解析 (跳过 RSV, FRAG)
	// 解析地址以确定数据起始偏移
	addr := SplitAddr(buf[3:])
	if addr == nil {
		return 0, fmt.Errorf("invalid socks udp header")
	}
	
	dataOffset := 3 + len(addr)
	copy(b, buf[dataOffset:n])
	return n - dataOffset, nil
}

func (c *socksUDPConn) Close() error {
	_ = c.ctrlConn.Close()
	return c.UDPConn.Close()
}

// ClientConnect performs a SOCKS5 client CONNECT handshake over an existing
// TCP connection to a SOCKS5 server. On success the provided conn is now a
// proxied connection to target and may be used to send/receive application
// data. This is intended to be used with a pre-established TCP connection to
// the SOCKS server (e.g. from a warm connection pool).
func ClientConnect(conn net.Conn, target string) error {
	// greeting: VER, NMETHODS, METHODS
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	buf := make([]byte, MaxAddrLen)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return err
	}
	if buf[1] == 0xFF {
		return ErrConnectionNotAllowed
	}

	addr := ParseAddr(target)
	if addr == nil {
		return ErrAddressNotSupported
	}

	req := append([]byte{5, 1, 0}, addr...)
	if _, err := conn.Write(req); err != nil {
		return err
	}

	// read reply header
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return err
	}
	if buf[1] != 0x00 {
		return Error(buf[1])
	}
	// consume bind addr
	if _, err := readAddr(conn, make([]byte, MaxAddrLen)); err != nil {
		return err
	}

	return nil
}
