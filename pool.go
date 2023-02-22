package CVLAN

import (
	"bytes"
	"github.com/cvlan/core/internal/sync"
)

var (
	bytesBufferPool = sync.NewPool[*bytes.Buffer](func() *bytes.Buffer {
		return &bytes.Buffer{}
	}, nil, func(val *bytes.Buffer) {
		val.Reset()
	})
)
