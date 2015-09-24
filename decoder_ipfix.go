package netflow

import "io"

// IPFIXDecoder for decoding IPFIX messages. For the decoder to be able
// to interpret Data FlowSets, the decoder needs access to a shared template
// cache. It's up to the caller how to implement said cache.
type IPFIXDecoder struct {
	io.Reader
	// Cache for looking up and storing templates. To be overridden by the caller.
	//Cache    V9TemplateCache
	Header   *IPFIXMessageHeader
	flowsets []interface{}
}

// NewIPFIXDecoder decodes the IPFIX packet header and sets up a decoder for the Export Records in the packet.
func NewIPFIXDecoder(r io.Reader) (*IPFIXDecoder, error) {
	d := &IPFIXDecoder{
		Reader: r,
		Header: new(IPFIXMessageHeader),
	}
	return d, d.Header.Unmarshal(d.Reader)
}

func (d *IPFIXDecoder) Len() int {
	return 0
}

func (d *IPFIXDecoder) Next() (ExportRecord, error) {
	return nil, nil
}

func (d *IPFIXDecoder) NextFlow() (ExportRecord, error) {
	return nil, nil
}

func (d *IPFIXDecoder) SampleRate() int {
	return 1
}

func (d *IPFIXDecoder) Version() uint16 {
	return VersionIPFIX
}
