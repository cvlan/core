package packet

import (
	"io"
)

type Encoding interface {
	Encoder(w io.Writer) error
	Decoder(r io.Reader) error
}

type Packet struct {
	Header *Header
	Data   []byte
}

func (p *Packet) Encoder(w io.Writer) (err error) {
	if err = p.Header.Encoder(w); err != nil {
		return
	}
	buf := bytesBufferPool.Alloc()
	buf.Val().Write(p.Data)
	_, err = io.Copy(w, buf.Val())
	buf.Free()
	return
}

func (p *Packet) Decoder(r io.Reader) (err error) {
	if err = p.Header.Decoder(r); err != nil {
		return
	}
	buf := bytesBufferPool.Alloc()
	_, err = io.Copy(buf.Val(), r)
	p.Data = buf.Val().Bytes()
	buf.Free()
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
		Data: nil,
	}
}

func NewPacketReader(r io.Reader) (*Packet, error) {
	packet := NewPacket()
	if err := packet.Decoder(r); err != nil {
		return nil, err
	}
	return packet, nil
}
