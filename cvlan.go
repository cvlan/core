package CVLAN

import (
	"CVLAN/crypto"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"time"
)

type Conn struct {
	SessionSecret []byte

	crypt      crypto.AES
	readBuffer *bytes.Buffer
	ctx        context.Context
	cancelFunc context.CancelFunc

	conn *net.TCPConn

	Timeout time.Duration
}

func (c *Conn) write(r io.Reader) (int64, error) {
	c.conn.SetWriteDeadline(time.Now().Add(c.Timeout))
	defer c.conn.SetWriteDeadline(time.Time{})
	return c.conn.ReadFrom(r)
}

func (c *Conn) read(w io.Writer) (n int64, err error) {
	buf := make([]byte, 512)
	for {
		c.conn.SetReadDeadline(time.Now().Add(c.Timeout))
		nr, er := c.conn.Read(buf)
		c.conn.SetReadDeadline(time.Time{})
		switch {
		case er != nil:
			err = er
			return
		case nr == 512:
			nw, ew := w.Write(buf)
			if nw > 0 {
				n += int64(nw)
			}
			if ew != nil {
				err = ew
				return
			}
		case n < 512:
			nw, ew := w.Write(buf[:nr])
			if nw > 0 {
				n += int64(nw)
			}
			if ew != nil {
				err = ew
				return
			}
			return
		default:
			err = errors.New("readFull failed")
			return
		}
	}
}

func (c *Conn) WriteAsBytes(b []byte) (int64, error) {
	buf := bytes.NewBuffer(b)
	defer func() { buf = nil }()
	return c.write(buf)
}

func (c *Conn) ReadAsBytes() ([]byte, error) {
	buf := bytesBufferPool.Alloc()
	defer buf.Free()
	_, err := c.read(buf.Val())
	if err != nil {
		return nil, err
	}
	return buf.Val().Bytes(), nil
}

func (c *Conn) Close() error {
	c.cancelFunc()
	return c.conn.Close()
}

type ClientCfg struct {
	Context context.Context
	Conn    *net.TCPConn
	Timeout time.Duration
}

func NewClient(cfg *ClientCfg) (*Conn, error) {

	return nil, nil
}
