package packet

import (
	"bytes"
	"io"
)

type Encoding interface {
	Encoder(w io.Writer) error
	Decoder(r io.Reader) error
}

type Packet struct {
	Header *Header
	Data   io.ReadWriter
}

func (p *Packet) Encoder(w io.Writer) (err error) {
	if err = p.Header.Encoder(w); err != nil {
		return
	}
	_, err = io.Copy(w, p.Data)
	return
}

func (p *Packet) Decoder(r io.Reader) (err error) {
	if err = p.Header.Decoder(r); err != nil {
		return
	}
	_, err = io.Copy(p.Data, r)
	return
}

func NewPacket() *Packet {
	return &Packet{
		Header: &Header{
			Len:     0,
			SrcType: IPv4,
			DstType: IPv4,
			SrcPort: 0,
			DstPort: 0,
			Src:     []byte{0, 0, 0, 0},
			Dst:     []byte{0, 0, 0, 0},
		},
		Data: &bytes.Buffer{},
	}
}

func NewPacketReader(r io.Reader) (*Packet, error) {
	packet := NewPacket()
	if err := packet.Decoder(r); err != nil {
		return nil, err
	}
	return packet, nil
}
