package netflow

import "io"

type V1Decoder struct {
	io.Reader
	header *V1Header
	index  uint16
}

func NewV1Decoder(r io.Reader) *V1Decoder {
	return &V1Decoder{
		Reader: r,
		header: new(V1Header),
	}
}

func (d *V1Decoder) DecodeHeader() error {
	return d.header.Unmarshal(d.Reader)
}

func (d *V1Decoder) Flows(flows chan FlowRecord) error {
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

func (d *V1Decoder) next() (f FlowRecord, err error) {
	if d.header.Version == 0 {
		if err = d.DecodeHeader(); err != nil {
			return
		}
	}

	if d.index >= d.header.Count {
		return nil, io.EOF
	}

	var flow = new(V1FlowRecord)
	d.index++
	return flow, flow.Unmarshal(d.Reader)
}

func (d *V1Decoder) SampleInterval() int {
	return 1
}

func (d *V1Decoder) SetVersion(v uint16) error {
	if d.header.Version == versionUnknown {
		d.header.Version = v
		return d.header.Unmarshal(d.Reader)
	}

	d.header.Version = v
	return nil
}
