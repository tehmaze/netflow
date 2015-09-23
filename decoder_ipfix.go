package netflow

import "io"

// IPFIXDecoder for decoding IPFIX messages. For the decoder to be able
// to interpret Data FlowSets, the decoder needs access to a shared template
// cache. It's up to the caller how to implement said cache.
type IPFIXDecoder struct {
	io.Reader
	// Cache for looking up and storing templates. To be overridden by the caller.
	//Cache    V9TemplateCache
	header   *IPFIXMessageHeader
	flowsets []interface{}
}

func NewIPFIXDecoder(r io.Reader) *IPFIXDecoder {
	return &IPFIXDecoder{
		Reader: r,
		//Cache:  make(V9TemplateCache),
		header: new(IPFIXMessageHeader),
	}
}

func (d *IPFIXDecoder) ensureHeader() error {
	if d.header.Version == versionUnknown {
		return d.header.Unmarshal(d.Reader)
	}

	return nil
}

func (d *IPFIXDecoder) ensureVersion() (err error) {
	if err = d.ensureHeader(); err == nil {
		if d.header.Version != 10 {
			err = errorIncompatibleVersion(d.header.Version, 10)
		}
	}
	return
}

func (d *IPFIXDecoder) Flows(flows chan FlowRecord) error {
	if err := d.ensureVersion(); err != nil {
		return err
	}

	flows <- d.header

	return nil
}

func (d *IPFIXDecoder) SampleInterval() int {
	return 1
}

func (d *IPFIXDecoder) SetVersion(v uint16) error {
	if d.header.Version == versionUnknown {
		d.header.Version = v
		return d.header.Unmarshal(d.Reader)
	}

	d.header.Version = v
	return nil
}
