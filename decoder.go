package netflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

func errorIncompatibleVersion(v, e uint16) error {
	return fmt.Errorf("netflow: incompatible protocol version %d, expected %d", v, e)
}

// Decoder is a deterministic decoder that can decode NetFlow versions 1, 5, 7, 8 and 9.
type Decoder struct {
	io.Reader
}

// VersionDecoder implements the actual version specific decoder.
type VersionDecoder interface {
	// Flows will decode all the flow records and stream them into the flows channel
	Flows(chan FlowRecord) error
	// SetVersion set the Version word in the packet header
	SetVersion(uint16) error
	// SampleInverval returns the sample interval in seconds
	SampleInterval() int
}

// NewDecoder creates a new deterministic decoder. It reads the first word to
// determine the decoder version, for which a decoder can be requested with
// the Decoder method.
func NewDecoder() *Decoder {
	return &Decoder{}
}

// Decoder returns a version specific flow record decoder.
func (d *Decoder) Decode(data []byte) (VersionDecoder, error) {
	buffer := bytes.NewBuffer(data)

	var version uint16
	var err error
	if version, err = readUint16(buffer); err != nil {
		return nil, err
	}

	var v VersionDecoder
	switch version {
	case 1:
		v = NewV1Decoder(buffer)
	case 5:
		v = NewV5Decoder(buffer)
	case 8:
		v = NewV8Decoder(buffer)
	case 9:
		v = NewV9Decoder(buffer)
	default:
		return nil, fmt.Errorf("netflow version %d is not supported", version)
	}

	return v, v.SetVersion(version)
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
