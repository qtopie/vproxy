package internal

import (
	"net"
	"testing"
)

type halfCloseConn struct {
	net.Conn
	closedWrite bool
}

func (c *halfCloseConn) CloseWrite() error {
	c.closedWrite = true
	return nil
}

func TestCloseWriteUsesHalfCloseInterface(t *testing.T) {
	conn := &halfCloseConn{Conn: &mockConn{}}

	closeWrite(conn)

	if !conn.closedWrite {
		t.Fatal("expected CloseWrite to be used when the connection supports it")
	}
}

func TestCloseWriteClosesConnectionsWithoutHalfClose(t *testing.T) {
	conn := &closeTrackingConn{Conn: &mockConn{}}

	closeWrite(conn)

	if !conn.closed {
		t.Fatal("expected Close to be used when CloseWrite is unavailable")
	}
}

type closeTrackingConn struct {
	net.Conn
	closed bool
}

func (c *closeTrackingConn) Close() error {
	c.closed = true
	return nil
}

var _ net.Conn = (*halfCloseConn)(nil)
var _ net.Conn = (*closeTrackingConn)(nil)
