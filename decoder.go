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

// FlowDecoder implements the actual version specific decoder.
type FlowDecoder interface {
	// Len returns the number of Export Records in the decoded packet.
	Len() int
	// Next returns the next Export Record in the decoded packet.
	Next() (ExportRecord, error)
	// Version returns the flow decoder version.
	Version() uint16
	// SampleRate returns the sample interval in seconds.
	SampleRate() int
}

// NewDecoder creates a new deterministic decoder. It reads the first word to
// determine the decoder version, for which a decoder can be requested with
// the Decoder method.
func NewDecoder() *Decoder {
	return &Decoder{}
}

// Decode returns a version specific flow record decoder.
func (d *Decoder) Decode(data []byte) (FlowDecoder, error) {
	buffer := bytes.NewBuffer(data)
	if buffer.Len() < 2 {
		return nil, io.ErrShortBuffer
	}

	v := binary.BigEndian.Uint16(buffer.Bytes()[:2])
	switch v {
	case 1:
		return NewV1Decoder(buffer)
	case 5:
		return NewV5Decoder(buffer)
	case 6:
		return NewV6Decoder(buffer)
	case 7:
		return NewV7Decoder(buffer)
	case 8:
		return NewV8Decoder(buffer)
	case 9:
		return NewV9Decoder(buffer)
	case 10:
		return NewIPFIXDecoder(buffer)
	default:
		return nil, fmt.Errorf("netflow version %d is not supported", v)
	}
}
