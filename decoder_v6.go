package netflow

import "io"

// V6Decoder can decode NetFlow version 6 packets.
type V6Decoder struct {
	io.Reader
	Header *V6Header
	index  uint16
}

// NewV6Decoder decodes the NetFlow version 6 packet header and sets up a decoder for the Export Records in the packet.
func NewV6Decoder(r io.Reader) (*V6Decoder, error) {
	d := &V6Decoder{
		Reader: r,
		Header: new(V6Header),
	}
	return d, d.Header.Unmarshal(d.Reader)
}

// Len returns the number of Export Records in the decoded packet.
func (d *V6Decoder) Len() int {
	return int(d.Header.Count)
}

// Next returns the next Export Record.
func (d *V6Decoder) Next() (ExportRecord, error) {
	if d.index == d.Header.Count {
		return nil, io.EOF
	}

	d.index++
	record := new(V6FlowRecord)
	return record, record.Unmarshal(d.Reader)
}

func (d *V6Decoder) SampleRate() int {
	return int(d.Header.SamplingInterval)
}

func (d *V6Decoder) Version() uint16 {
	return Version5
}
