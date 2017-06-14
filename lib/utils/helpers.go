package utils

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
)

var (
	put32 = binary.LittleEndian.PutUint32
	put16 = binary.LittleEndian.PutUint16
	//EncBase64 wrapper for encoding to base64
	EncBase64 = base64.StdEncoding.EncodeToString
	//DecBase64 wrapper for decoding from base64
	DecBase64 = base64.StdEncoding.DecodeString
)

//DecodeUint16 decode 2 byte value into uint16
func DecodeUint16(num []byte) uint16 {
	var number uint16
	bf := bytes.NewReader(num)
	binary.Read(bf, binary.LittleEndian, &number)
	return number
}
