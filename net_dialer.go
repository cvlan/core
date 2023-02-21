package CVLAN

import (
	"crypto/tls"
	"net"
)

func NewTCPDialer(addr string) (*net.TCPConn, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	return net.DialTCP("tcp", nil, tcpAddr)
}

func NewTCPDialerWithTLS(addr string, cfg *tls.Config) (*tls.Conn, error) {
	return tls.Dial("tcp", addr, cfg)
}
