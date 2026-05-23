package internal

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
)

// Relay copies between left and right bidirectionally
func Relay(ctx context.Context, left, right net.Conn) error {
	var wg sync.WaitGroup
	var errLeft, errRight error
	wg.Add(2)

	closer := func() {
		_ = left.Close()
		_ = right.Close()
	}

	go func() {
		defer wg.Done()
		defer closer()
		var n int64
		n, errLeft = io.Copy(right, left)
		TraceDebugf(ctx, ">>> TUN -> SOCKS: copied %d bytes, err: %v", n, errLeft)
	}()

	go func() {
		defer wg.Done()
		defer closer()
		var n int64
		n, errRight = io.Copy(left, right)
		TraceDebugf(ctx, "<<< SOCKS -> TUN: copied %d bytes, err: %v", n, errRight)
	}()

	wg.Wait()

	if errLeft != nil && !isIgnorableError(errLeft) {
		return errLeft
	}
	if errRight != nil && !isIgnorableError(errRight) {
		return errRight
	}
	return nil
}

// isIgnorableError checks if an error is an expected close signal (EOF or timeout).
func isIgnorableError(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) {
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
