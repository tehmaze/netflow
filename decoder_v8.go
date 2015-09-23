package netflow

import "io"

type V8Decoder struct {
	io.Reader
	header V8Header
	index  uint16
}

func NewV8Decoder(r io.Reader) *V8Decoder {
	return &V8Decoder{
		Reader: r,
	}
}

func (d *V8Decoder) DecodeHeader() (err error) {
	return d.header.Unmarshal(d.Reader)
}

func (d *V8Decoder) Flows(flows chan FlowRecord) error {
	if d.header.Version == 0 {
		if err := d.DecodeHeader(); err != nil {
			return err
		}
	}

	for d.index < d.header.Count {
		var flow FlowRecord
		var err error
		if flow, err = d.next(); err != nil {
			return err
		}

		flows <- flow
	}

	return nil
}

func (d *V8Decoder) next() (f FlowRecord, err error) {
	return
}

func (d *V8Decoder) SampleInterval() int {
	return 0
}

func (d *V8Decoder) SetVersion(v uint16) error {
	if d.header.Version == versionUnknown {
		d.header.Version = v
		return d.header.Unmarshal(d.Reader)
	}
	d.header.Version = v
	return nil
}
