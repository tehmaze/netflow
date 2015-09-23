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

func (d *V5Decoder) ensureHeader() (err error) {
	if d.header.Version == versionUnknown {
		err = d.header.Read(d.Reader)
	}
	return
}

func (d *V5Decoder) ensureVersion() (err error) {
	if err = d.ensureHeader(); err == nil {
		if d.header.Version != 5 {
			err = errorIncompatibleVersion(d.header.Version, 5)
		}
	}
	return
}

func (d *V5Decoder) DecodeHeader() (err error) {
	return d.header.Read(d.Reader)
}

func (d *V5Decoder) Flows(flows chan FlowRecord) (err error) {
	if err = d.ensureVersion(); err != nil {
		return
	}

	for d.index < d.header.Count {
		var flow FlowRecord
		if flow, err = d.next(); err != nil {
			return
		}

		flows <- flow
	}

	return
}

func (d *V5Decoder) next() (f FlowRecord, err error) {
	if d.header.Version == 0 {
		if err = d.DecodeHeader(); err != nil {
			return
		}
	}

	if d.index >= d.header.Count {
		return nil, io.EOF
	}

	var flow = new(V5FlowRecord)
	d.index++
	return flow, flow.Read(d.Reader)
}

func (d *V5Decoder) SampleInterval() int {
	return int(d.header.SamplingInterval)
}

func (d *V5Decoder) SetVersion(v uint16) (err error) {
	if d.header.Version == versionUnknown {
		d.header.Version = v
		err = d.header.Read(d.Reader)
	}
	d.header.Version = v
	return
}
