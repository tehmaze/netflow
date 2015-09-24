package netflow

import "io"

// V1Decoder can decode NetFlow version 1 packets.
type V1Decoder struct {
	io.Reader
	Header *V1Header
	index  uint16
}

// NewV1Decoder decodes the NetFlow version 1 packet header and sets up a decoder for the Export Records in the packet.
func NewV1Decoder(r io.Reader) (*V1Decoder, error) {
	d := &V1Decoder{
		Reader: r,
		Header: new(V1Header),
	}
	return d, d.Header.Unmarshal(d.Reader)
}

// Len returns the number of Export Records in the decoded packet.
func (d *V1Decoder) Len() int {
	return int(d.Header.Count)
}

// Next returns the next Export Record.
func (d *V1Decoder) Next() (ExportRecord, error) {
	if d.index == d.Header.Count {
		return nil, io.EOF
	}

	d.index++
	record := new(V1FlowRecord)
	return record, record.Unmarshal(d.Reader)
}

// SampleRate returns the guessed sampling rate. Not available in NetFlow version 1.
func (d *V1Decoder) SampleRate() int {
	return 1
}

// Version returns the expected version word in the frame.
func (d *V1Decoder) Version() uint16 {
	return Version1
}
