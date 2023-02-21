package packet

import (
	"CVLAN/util"
	"io"
	"net"
)

type Length uint32

func (l *Length) Encoder(w io.Writer) error {
	_, err := w.Write(util.TypeEncoder[uint32](uint32(*l)))
	return err
}

func (l *Length) Decoder(r io.Reader) error {
	p := make([]byte, 4)
	_, err := r.Read(p)
	if err != nil {
		return err
	}
	*l = Length(util.TypeDecoder[uint32](p))
	return nil
}

type Header struct {
	Protocol Protocol
	SrcType  IPType
	DstType  IPType
	SrcPort  Port
	DstPort  Port
	Len      Length

	Src net.IP
	Dst net.IP
}

func (h *Header) ipReader(r io.Reader, ptr *net.IP, isV6 bool) error {
	p := make([]byte, 4)
	if isV6 {
		p = nil
		p = make([]byte, 16)
	}

	if _, err := r.Read(p); err != nil {
		return err
	}

	*ptr = p

	return nil
}

func (h *Header) Encoder(w io.Writer) (err error) {
	// write src,dst IPType and Port
	encoders := []Encoding{
		&h.Protocol,
		&h.SrcType,
		&h.DstType,
		&h.SrcPort,
		&h.DstPort,
		&h.Len,
	}
	for i := 0; i < 6; i++ {
		if err = encoders[i].Encoder(w); err != nil {
			return err
		}
	}

	// write ip addr
	if _, err = w.Write(h.Src); err != nil {
		return err
	}
	if _, err = w.Write(h.Dst); err != nil {
		return err
	}
	return
}

func (h *Header) Decoder(r io.Reader) (err error) {
	// read src,dst IPType and Port
	decoders := []Encoding{
		&h.Protocol,
		&h.SrcType,
		&h.DstType,
		&h.SrcPort,
		&h.DstPort,
		&h.Len,
	}
	for i := 0; i < 6; i++ {
		if err = decoders[i].Decoder(r); err != nil {
			return err
		}
	}

	// read ip addr
	if err = h.ipReader(r, &h.Src, h.SrcType.IsIPv6()); err != nil {
		return
	}
	if err = h.ipReader(r, &h.Dst, h.DstType.IsIPv6()); err != nil {
		return
	}

	return
}
