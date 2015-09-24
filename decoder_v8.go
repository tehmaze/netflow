package netflow

import "io"

// V8Decoder can decode NetFlow version 8 frames.
type V8Decoder struct {
	io.Reader
	Header *V8Header
	index  uint16
}

func NewV8Decoder(r io.Reader) (*V8Decoder, error) {
	d := &V8Decoder{
		Reader: r,
		Header: new(V8Header),
	}
	return d, d.Header.Unmarshal(r)
}

// Len returns the number of Export Records in the decoded packet.
func (d *V8Decoder) Len() int {
	return int(d.Header.Count)
}

// Next returns the next Export Record.
func (d *V8Decoder) Next() (ExportRecord, error) {
	return nil, io.EOF
}

func (d *V8Decoder) SampleRate() int {
	return 0
}

func (d *V8Decoder) Version() uint16 {
	return Version8
}
