package netflow

import (
	"encoding/binary"
	"io"
	"net"
)

type LongIPv4 uint32

func (l LongIPv4) String() string {
	return net.IP{
		uint8(l >> 24),
		uint8(l >> 16),
		uint8(l >> 8),
		uint8(l),
	}.String()
}

func readUint8(r io.Reader) (uint8, error) {
	var b [1]byte
	_, err := io.ReadFull(r, b[:])
	return b[0], err
}

func readUint16(r io.Reader) (uint16, error) {
	var b [2]byte
	_, err := io.ReadFull(r, b[:])
	return binary.BigEndian.Uint16(b[:]), err
}

func readUint32(r io.Reader) (uint32, error) {
	var b [4]byte
	_, err := io.ReadFull(r, b[:])
	return binary.BigEndian.Uint32(b[:]), err
}

func readUint64(r io.Reader) (uint64, error) {
	var b [8]byte
	_, err := io.ReadFull(r, b[:])
	return binary.BigEndian.Uint64(b[:]), err
}

func readLongIPv4(r io.Reader) (LongIPv4, error) {
	l, err := readUint32(r)
	return LongIPv4(l), err
}
