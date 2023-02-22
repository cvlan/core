package CVLAN

import (
	"bytes"
	"context"
	"errors"
	"github.com/cvlan/core/crypto"
	"io"
	"net"
	"time"
)

type Conn struct {
	SessionSecret []byte

	crypt      crypto.AES
	readBuffer *bytes.Buffer
	ctx        context.Context
	cancelFunc context.CancelCauseFunc

	conn *net.TCPConn

	Timeout time.Duration
}

func (c *Conn) handshake(hs ...HandShake) (err error) {
	for _, h := range hs {
		if err = h.Do(); err != nil {
			return
		}
	}
	return
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

func (c *Conn) Read(p []byte) (n int, err error) {
Start:
	if c.readBuffer.Len() == 0 {
		goto Read
	}
	return c.readBuffer.Read(p)

Read:
	rbuf := bytesBufferPool.Alloc()
	defer rbuf.Free()
	for {
		if c.readBuffer.Len() > 0 {
			goto Start
		}

		if _, err = c.read(rbuf.Val()); err != nil {
			if err == io.EOF {
				goto Start
			}
			return
		}

		if err = c.crypt.StreamDecrypt(rbuf.Val(), c.readBuffer, nil); err != nil {
			return
		}
	}
}

func (c *Conn) Write(p []byte) (n int, err error) {
	cryptBuf := bytesBufferPool.Alloc()
	defer cryptBuf.Free()
	err = c.crypt.StreamEncrypt(bytes.NewReader(p), cryptBuf.Val(), nil)
	if err != nil {
		return 0, err
	}
	nn, err := io.Copy(c.conn, cryptBuf.Val())
	return int(nn), err
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
	c.cancelFunc(errors.New("connect close"))
	return c.conn.Close()
}

func makeConnect(ctx context.Context, conn *net.TCPConn, timeout time.Duration) *Conn {
	ctx, cancel := context.WithCancelCause(ctx)
	return &Conn{
		SessionSecret: nil,
		crypt:         nil,
		readBuffer:    &bytes.Buffer{},
		ctx:           ctx,
		cancelFunc:    cancel,
		conn:          conn,
		Timeout:       timeout,
	}
}

type ClientCfg struct {
	Context context.Context
	Conn    *net.TCPConn
	Timeout time.Duration
}

func NewClient(cfg *ClientCfg) (*Conn, error) {
	conn := makeConnect(cfg.Context, cfg.Conn, cfg.Timeout)

	clientHandshake := &ClientHandshake{}
	if err := conn.handshake(
		clientHandshake.ECDH(conn),
		clientHandshake.Verify(conn),
	); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

type ServerCfg struct {
	Context context.Context
	Conn    *net.TCPConn
	Timeout time.Duration
}

func NewServer(cfg *ServerCfg) (*Conn, error) {
	conn := makeConnect(cfg.Context, cfg.Conn, cfg.Timeout)

	serverHandshake := &ServerHandshake{}
	if err := conn.handshake(
		serverHandshake.ECDH(conn),
		serverHandshake.Verify(conn),
	); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}
