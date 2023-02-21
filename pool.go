package CVLAN

import (
	"CVLAN/internal/sync"
	"bytes"
)

var (
	bytesBufferPool = sync.NewPool[*bytes.Buffer](func() *bytes.Buffer {
		return &bytes.Buffer{}
	}, nil, func(val *bytes.Buffer) {
		val.Reset()
	})
)
