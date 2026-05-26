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

// Relay copies between left and right bidirectionally
func Relay(ctx context.Context, left, right net.Conn) error {
	var wg sync.WaitGroup
	var errLeft, errRight error
	wg.Add(2)

	go func() {
		defer wg.Done()
		var n int64
		n, errLeft = io.Copy(right, left)
		TraceDebugf(ctx, ">>> L -> R: copied %d bytes, err: %v", n, errLeft)
		_ = right.Close() // Notify the other side we are done writing
	}()

	go func() {
		defer wg.Done()
		var n int64
		n, errRight = io.Copy(left, right)
		TraceDebugf(ctx, "<<< R -> L: copied %d bytes, err: %v", n, errRight)
		_ = left.Close() // Notify the other side we are done writing
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
