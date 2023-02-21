package packet_test

import (
	"CVLAN/packet"
	"bytes"
	"io"
	"testing"
)

func TestNewPacket(t *testing.T) {
	pkt := packet.NewPacket()
	t.Log(pkt)
}

func TestNewPacketReader(t *testing.T) {

	pkt := packet.NewPacket()
	pkt.Header.Protocol = packet.TCP
	pkt.Header.SrcType = packet.IPv4
	pkt.Header.DstType = packet.IPv4
	pkt.Header.SrcPort = 51312
	pkt.Header.DstPort = 8080
	pkt.Header.Len = 5
	pkt.Header.Src = []byte{192, 168, 0, 1}
	pkt.Header.Dst = []byte{223, 5, 5, 5}
	pkt.Data.Write([]byte("Hello"))

	t.Log(*pkt.Header)
	buf := &bytes.Buffer{}
	if err := pkt.Encoder(buf); err != nil {
		t.Fatal(err)
	}
	t.Log(buf.Bytes())

	rpkt, err := packet.NewPacketReader(buf)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(*rpkt.Header)
	data, _ := io.ReadAll(rpkt.Data)
	t.Log(string(data))

}

func BenchmarkPacket_Encoder(b *testing.B) {

	pkt := packet.NewPacket()
	pkt.Header.Protocol = packet.TCP
	pkt.Header.SrcType = packet.IPv4
	pkt.Header.DstType = packet.IPv4
	pkt.Header.SrcPort = 51312
	pkt.Header.DstPort = 8080
	pkt.Header.Len = 5
	pkt.Header.Src = []byte{192, 168, 0, 1}
	pkt.Header.Dst = []byte{223, 5, 5, 5}
	pkt.Data.Write([]byte("Hello"))

	buf := bytes.Buffer{}

	for i := 0; i < b.N; i++ {
		if err := pkt.Encoder(&buf); err != nil {
			b.Fatal(err)
		}
	}

}
