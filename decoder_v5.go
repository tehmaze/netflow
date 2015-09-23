package netflow

import "io"

type V5Decoder struct {
	io.Reader
	header V5Header
	index  uint16
}

func NewV5Decoder(r io.Reader) *V5Decoder {
	return &V5Decoder{
		Reader: r,
	}
}

func (d *V5Decoder) ensureHeader() error {
	if d.header.Version == versionUnknown {
		return d.header.Unmarshal(d.Reader)
	}
	return nil
}

func (d *V5Decoder) ensureVersion() error {
	if err := d.ensureHeader(); err != nil {
		return err
	}
	if d.header.Version != 5 {
		return errorIncompatibleVersion(d.header.Version, 5)
	}
	return nil
}

func (d *V5Decoder) DecodeHeader() error {
	return d.header.Unmarshal(d.Reader)
}

func (d *V5Decoder) Flows(flows chan FlowRecord) error {
	if err := d.ensureVersion(); err != nil {
		return err
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

func (d *V5Decoder) next() (FlowRecord, error) {
	if d.header.Version == 0 {
		if err := d.DecodeHeader(); err != nil {
			return nil, err
		}
	}

	if d.index >= d.header.Count {
		return nil, io.EOF
	}

	var flow = new(V5FlowRecord)
	d.index++
	return flow, flow.Unmarshal(d.Reader)
}

func (d *V5Decoder) SampleInterval() int {
	return int(d.header.SamplingInterval)
}

func (d *V5Decoder) SetVersion(v uint16) error {
	if d.header.Version == versionUnknown {
		d.header.Version = v
		return d.header.Unmarshal(d.Reader)
	}
	d.header.Version = v
	return nil
}
