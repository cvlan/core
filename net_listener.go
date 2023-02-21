package CVLAN

import (
	"crypto/tls"
	"net"
)

func NewTCPListener(addr string) (*net.TCPListener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	return net.ListenTCP("tcp", tcpAddr)
}

func NewTCPListenerWithTLS(addr string, cfg *tls.Config) (*net.TCPListener, error) {
	listener, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	return listener.(*net.TCPListener), nil
}
