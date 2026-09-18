//go:build linux
// +build linux

package driver

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/qtopie/vproxy/proxy/tproxy"
)

type linuxDriver struct {
	cfg DriverConfig
}

// NewDriver creates the Linux-specific InterceptDriver.
func NewDriver(cfg DriverConfig) InterceptDriver {
	return &linuxDriver{cfg: cfg}
}

func (d *linuxDriver) Name() string {
	if d.cfg.IsTUN || os.Getenv("VP_USE_TUN") == "1" {
		return "linux-tun"
	}
	return "linux-redirect"
}

func (d *linuxDriver) Start(ctx context.Context, onTCP ConnectionCallback, onUDP ConnectionCallback) error {
	if d.cfg.IsTUN || os.Getenv("VP_USE_TUN") == "1" {
		return tproxy.StartLinuxTransparent(ctx, func(conn net.Conn) {
			defer conn.Close()
			target, err := tproxy.GetOriginalDst(conn)
			if err != nil {
				log.Printf("[TUN/L] Failed to get original destination: %v", err)
				return
			}
			onTCP(conn, target)
		}, func(ctx context.Context, local net.Conn, target string) {
			onUDP(local, target)
		})
	}

	// Local transparent TCP listener
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", d.cfg.TransPort))
	if err != nil {
		log.Printf("Transparent proxy port %d is in use, binding to free port...", d.cfg.TransPort)
		ln, err = net.Listen("tcp", ":0")
		if err != nil {
			return err
		}
	}
	d.cfg.TransPort = ln.Addr().(*net.TCPAddr).Port
	log.Printf("Transparent TCP proxy listening on %d (mode: redirect)", d.cfg.TransPort)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				target, err := tproxy.GetOriginalDst(c)
				if err != nil {
					log.Printf("Failed to get original destination: %v", err)
					return
				}
				onTCP(c, target)
			}(conn)
		}
	}()

	// Local transparent UDP listener
	udpLn, err := tproxy.ListenUDPTransparent(d.cfg.TransPort)
	if err != nil {
		log.Printf("Failed to listen transparent UDP on %d: %v", d.cfg.TransPort, err)
	} else {
		go func() {
			buf := make([]byte, 65535)
			oob := make([]byte, 1024)
			for {
				n, src, dst, err := tproxy.ReadFromUDPWithOrigDst(udpLn, buf, oob)
				if err != nil {
					return
				}
				if dst == nil {
					continue
				}
				_ = n
				_ = src
				// Packet handling is managed by onUDP or handler
			}
		}()
	}

	return nil
}

func (d *linuxDriver) Cleanup() error {
	tproxy.Cleanup()
	return nil
}

// linuxProcessInspector implements ProcessInspector on Linux.
type linuxProcessInspector struct{}

func NewProcessInspector() ProcessInspector {
	return &linuxProcessInspector{}
}

func (i *linuxProcessInspector) GetProcessNameByConn(conn net.Conn) (string, int, error) {
	return tproxy.GetProcessNameByConn(conn)
}

func (i *linuxProcessInspector) GetProcessNameByPort(port int) (string, int, error) {
	return tproxy.GetProcessNameByPort(port)
}

// linuxRelayDetector implements RelayDetector on Linux.
type linuxRelayDetector struct{}

func NewRelayDetector(_ []string) RelayDetector {
	return &linuxRelayDetector{}
}

func (r *linuxRelayDetector) IsForwardedRelay(_ net.Conn, _ bool, _ int) bool {
	return false
}
