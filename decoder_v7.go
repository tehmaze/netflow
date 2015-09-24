package netflow

import "io"

// V7Decoder can decode NetFlow version 7 frames (Cisco Catalyst 5000 series switches).
type V7Decoder struct {
	io.Reader
	// Header is the decoded NetFlow version 7 header
	Header *V7Header
	index  uint16
}

// NewV7Decoder decodes the NetFlow version 7 packet header and sets up a decoder for the Export Records in the packet.
func NewV7Decoder(r io.Reader) (*V7Decoder, error) {
	d := &V7Decoder{
		Reader: r,
		Header: new(V7Header),
	}
	return d, d.Header.Unmarshal(d.Reader)
}

// Len returns the number of Export Records in the decoded packet.
func (d *V7Decoder) Len() int {
	return int(d.Header.Count)
}

/// Next returns the next Export Record.
func (d *V7Decoder) Next() (ExportRecord, error) {
	if d.index == d.Header.Count {
		return nil, io.EOF
	}

	d.index++
	record := new(V7FlowRecord)
	return record, record.Unmarshal(d.Reader)
}

func (d *V7Decoder) SampleRate() int {
	return 1
}

func (d *V7Decoder) Version() uint16 {
	return Version7
}
