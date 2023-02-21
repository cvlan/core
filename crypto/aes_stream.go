package crypto

import (
	"CVLAN/util"
	"errors"
	"io"
)

type AEStreamHeadInfo struct {
	NonceSize  uint32 // 4 bytes
	BlockCount uint32 // 4 bytes
}

type AEStreamBlockInfo struct {
	Size  uint32 // 4 bytes
	Nonce []byte
}

type AEStream struct {
	Head      *AEStreamHeadInfo
	BlockInfo []*AEStreamBlockInfo
	Payload   [][]byte
}

func (s *AEStream) Iter(fn func(nonce, payload []byte) error) error {
	for i := 0; i < int(s.Head.BlockCount); i++ {
		if err := fn(s.BlockInfo[i].Nonce, s.Payload[i]); err != nil {
			return err
		}
	}
	return nil
}

func (s *AEStream) Append(nonce, payload []byte) error {
	if s.Head.NonceSize == 0 {
		s.Head.NonceSize = uint32(len(nonce))
	}
	if s.Head.NonceSize != uint32(len(nonce)) {
		return errors.New("invalid nonce size")
	}

	s.Head.BlockCount++
	s.BlockInfo = append(s.BlockInfo, &AEStreamBlockInfo{
		Size:  uint32(len(payload)),
		Nonce: nonce,
	})
	s.Payload = append(s.Payload, payload)

	return nil
}

func (s *AEStream) Decoding(r io.Reader) (err error) {
	// read head
	head := make([]byte, 8)
	if _, err = r.Read(head[:]); err != nil {
		return
	}
	s.Head.NonceSize = util.TypeDecoder[uint32](head[:4])
	s.Head.BlockCount = util.TypeDecoder[uint32](head[4:])

	// read block info
	block := make([]byte, (4+s.Head.NonceSize)*s.Head.BlockCount)
	if _, err = r.Read(block[:]); err != nil {
		return
	}
	// init block info slice and read payload
	s.BlockInfo = make([]*AEStreamBlockInfo, s.Head.BlockCount)
	s.Payload = make([][]byte, s.Head.BlockCount)
	for i := 0; i < int(s.Head.BlockCount); i++ {
		sBlock := block[i*int(4+s.Head.NonceSize) : (i+1)*int(4+s.Head.NonceSize)]
		s.BlockInfo[i] = &AEStreamBlockInfo{
			Size:  util.TypeDecoder[uint32](sBlock[:4]),
			Nonce: sBlock[4:],
		}

		s.Payload[i] = make([]byte, s.BlockInfo[i].Size)
		if _, err = r.Read(s.Payload[i][:]); err != nil {
			return
		}
	}

	return nil
}

func (s *AEStream) Encoding(w io.Writer) error {
	// write head first
	w.Write(util.TypeEncoder[uint32](s.Head.NonceSize))
	w.Write(util.TypeEncoder[uint32](s.Head.BlockCount))

	block := make([]byte, (4+s.Head.NonceSize)*s.Head.BlockCount)
	for i := 0; i < int(s.Head.BlockCount); i++ {
		sBlock := make([]byte, 4+s.Head.NonceSize)
		copy(sBlock[:4], util.TypeEncoder[uint32](s.BlockInfo[i].Size))
		copy(sBlock[4:], s.BlockInfo[i].Nonce)
		copy(block[i*int(4+s.Head.NonceSize):(i+1)*int(4+s.Head.NonceSize)], sBlock)
	}
	w.Write(block)

	for i := 0; i < int(s.Head.BlockCount); i++ {
		w.Write(s.Payload[i])
	}

	return nil
}

func NewAEStream() *AEStream {
	return &AEStream{
		Head:      &AEStreamHeadInfo{},
		BlockInfo: make([]*AEStreamBlockInfo, 0),
		Payload:   make([][]byte, 0),
	}
}

func ReadAEStream(r io.Reader) (*AEStream, error) {
	as := NewAEStream()
	if err := as.Decoding(r); err != nil {
		return nil, err
	}
	return as, nil
}
