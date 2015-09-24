package netflow

import "io"

// V5Decoder can decode NetFlow version 5 packets.
type V5Decoder struct {
	io.Reader
	Header *V5Header
	index  uint16
}

// NewV5Decoder decodes the NetFlow version 5 packet header and sets up a decoder for the Export Records in the packet.
func NewV5Decoder(r io.Reader) (*V5Decoder, error) {
	d := &V5Decoder{
		Reader: r,
		Header: new(V5Header),
	}
	return d, d.Header.Unmarshal(d.Reader)
}

// Len returns the number of Export Records in the decoded packet.
func (d *V5Decoder) Len() int {
	return int(d.Header.Count)
}

// Next returns the next Export Record.
func (d *V5Decoder) Next() (ExportRecord, error) {
	if d.index == d.Header.Count {
		return nil, io.EOF
	}

	d.index++
	record := new(V5FlowRecord)
	return record, record.Unmarshal(d.Reader)
}

func (d *V5Decoder) SampleRate() int {
	return int(d.Header.SamplingInterval)
}

func (d *V5Decoder) Version() uint16 {
	return Version5
}
