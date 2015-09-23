package netflow

import "io"

type V9TemplateCache map[uint16]*V9TemplateRecord

// V9Decoder for decoding NetFlow version 9 messages. For the decoder to be able
// to interpret Data FlowSets, the decoder needs access to a shared template
// cache. It's up to the caller how to implement said cache.
type V9Decoder struct {
	io.Reader
	// Cache for looking up and storing templates. To be overridden by the caller.
	Cache    V9TemplateCache
	header   V9FlowHeader
	flowsets []interface{}
}

func NewV9Decoder(r io.Reader) *V9Decoder {
	return &V9Decoder{
		Reader: r,
		Cache:  make(V9TemplateCache),
	}
}

func (d *V9Decoder) ensureHeader() (err error) {
	if d.header.Version == versionUnknown {
		err = d.header.Read(d.Reader)
	}
	return
}

func (d *V9Decoder) ensureVersion() (err error) {
	if err = d.ensureHeader(); err == nil {
		if d.header.Version != 9 {
			err = errorIncompatibleVersion(d.header.Version, 9)
		}
	}
	return
}

func (d *V9Decoder) parseFlowSets() (err error) {
	d.flowsets = make([]interface{}, 0, d.header.Count)

	for i := uint16(0); i < d.header.Count; i++ {
		d.flowsets = d.flowsets[0 : i+1]
		if d.flowsets[i], err = d.parseFlowSet(); err != nil {
			return
		}
	}

	return
}

func (d *V9Decoder) parseFlowSet() (set interface{}, err error) {
	var header V9FlowSetHeader
	if err = header.Unmarshal(d.Reader); err != nil {
		return
	}

	switch header.ID {
	case 0: // Template FlowSet
		return d.parseTemplateFlowSet(header)
	case 1: // Options Template FlowSet
		return d.parseOptionsTemplateFlowSet(header)
	default: // Data FlowSet
		return d.parseDataFlowSet(header)
	}
}

func (d *V9Decoder) parseTemplateFlowSet(h V9FlowSetHeader) (set interface{}, err error) {
	tfs := new(V9TemplateFlowSet)
	tfs.V9FlowSetHeader = h
	err = tfs.UnmarshalRecords(d.Reader)
	return
}

func (d *V9Decoder) parseOptionsTemplateFlowSet(h V9FlowSetHeader) (set interface{}, err error) {
	ofs := new(V9OptionsTemplateFlowSet)
	ofs.V9FlowSetHeader = h
	err = ofs.UnmarshalRecords(d.Reader)
	return
}

func (d *V9Decoder) parseDataFlowSet(h V9FlowSetHeader) (set interface{}, err error) {
	dfs := new(V9DataFlowSet)
	dfs.V9FlowSetHeader = h
	err = dfs.UnmarshalData(d.Reader)
	return dfs, err
}

func (d *V9Decoder) Flows(flows chan FlowRecord) (err error) {
	if err = d.ensureVersion(); err != nil {
		return
	}

	if d.flowsets == nil {
		d.parseFlowSets()
	}

	for _, flowset := range d.flowsets {
		switch f := flowset.(type) {
		case V9TemplateFlowSet:
			for _, r := range f.Records {
				if d.Cache[r.TemplateID] == nil {
					d.Cache[r.TemplateID] = r
				}
			}

		case V9DataFlowSet:
			if t, ok := d.Cache[f.ID]; ok {
				var records []V9FlowDataRecord
				if records, err = t.DecodeFlowSet(&f); err != nil {
					return
				}
				for _, flow := range records {
					flows <- flow
				}
			}
		}
	}

	return
}

func (d *V9Decoder) SampleInterval() int {
	return 1
}

func (d *V9Decoder) SetVersion(v uint16) (err error) {
	if d.header.Version == versionUnknown {
		d.header.Version = v
		err = d.header.Read(d.Reader)
	}
	d.header.Version = v
	return
}
