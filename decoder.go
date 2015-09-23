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
func (d *Decoder) Decode(data []byte) (v VersionDecoder, err error) {
	buffer := bytes.NewBuffer(data)

	var version uint16
	if err = binary.Read(buffer, binary.BigEndian, &version); err != nil {
		return
	}

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
		err = fmt.Errorf("netflow version %d is not supported", version)
		return
	}

	v.SetVersion(version)
	return
}

type WriteBackReader struct {
	io.Reader
	buffer []byte
}

func NewWriteBackReader(r io.Reader, data []byte) *WriteBackReader {
	return &WriteBackReader{r, data}
}

func (w *WriteBackReader) Read(p []byte) (n int, err error) {
	n = len(p)
	if n == 0 {
		return
	}

	var l = len(w.buffer)
	// If the allocated buffer is larger than our internal buffer, read the
	// entire buffer and continue reading
	if n > l {
		l = len(w.buffer)
		copy(w.buffer, p)
		w.buffer = []byte{}
		n, err = w.Reader.Read(p[l:n])
		n += l
		return
	}

	// The allocated buffer is smaller than our internal buffer, so we just copy
	// a partial slice and truncate our internal buffer
	copy(w.buffer[:n], p)
	w.buffer = w.buffer[n:len(w.buffer)]
	return
}

func (w *WriteBackReader) Write(p []byte) {
	w.buffer = append(w.buffer, p...)
}
