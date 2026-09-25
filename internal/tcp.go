package internal

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
)

// Relay copies between left and right bidirectionally and returns transferred byte counts.
func Relay(ctx context.Context, left, right net.Conn) error {
	_, _, err := RelayWithStats(ctx, left, right)
	return err
}

// RelayWithStats copies between left and right bidirectionally, returning (bytesLR, bytesRL, error).
func RelayWithStats(ctx context.Context, left, right net.Conn) (int64, int64, error) {
	var wg sync.WaitGroup
	var errLeft, errRight error
	var nLeft, nRight int64
	wg.Add(2)

	go func() {
		defer wg.Done()
		nLeft, errLeft = io.Copy(right, left)
		TraceDebugf(ctx, ">>> L -> R: copied %d bytes, err: %v", nLeft, errLeft)
		closeWrite(right)
	}()

	go func() {
		defer wg.Done()
		nRight, errRight = io.Copy(left, right)
		TraceDebugf(ctx, "<<< R -> L: copied %d bytes, err: %v", nRight, errRight)
		closeWrite(left)
	}()

	wg.Wait()

	if errLeft != nil && !isIgnorableError(errLeft) {
		return nLeft, nRight, errLeft
	}
	if errRight != nil && !isIgnorableError(errRight) {
		return nLeft, nRight, errRight
	}
	return nLeft, nRight, nil
}


func closeWrite(conn net.Conn) {
	if tcpConn, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = tcpConn.CloseWrite()
		return
	}
	_ = conn.Close()
}

// isIgnorableError checks if an error is an expected close signal (EOF or timeout).
func isIgnorableError(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	// "use of closed network connection" is expected when one side closes and the other is still reading/writing
	if strings.Contains(err.Error(), "use of closed network connection") {
		return true
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	return false
}
