package util

import (
	"bytes"
	"encoding/binary"
	"unsafe"
)

var ByteOrder = binary.BigEndian

type EncodeType interface {
	bool | int8 | int16 | int32 | int64 | int | uint8 | uint16 | uint32 | uint64 | uint | float32 | float64
}

func TypeEncoder[T EncodeType | *T](n T) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, ByteOrder, n)
	return buf.Bytes()
}

func TypeDecoder[T EncodeType | *T](b []byte) T {
	var n T
	binary.Read(bytes.NewReader(b), ByteOrder, &n)
	return n
}

func Bytes2String(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func String2Bytes(s string) []byte {
	a := (*[2]uintptr)(unsafe.Pointer(&s))
	b := [3]uintptr{a[0], a[1], a[1]}
	return *(*[]byte)(unsafe.Pointer(&b))
}
