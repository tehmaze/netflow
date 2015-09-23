package netflow

import (
	"bytes"
	"fmt"
	"io"
	"log"
)

type V9TemplateCache map[uint16]*V9TemplateRecord

// V9Decoder for decoding NetFlow version 9 messages. For the decoder to be able
// to interpret Data FlowSets, the decoder needs access to a shared template
// cache. It's up to the caller how to implement said cache.
type V9Decoder struct {
	io.Reader
	// Cache for looking up and storing templates. To be overridden by the caller.
	Cache    V9TemplateCache
	header   *V9FlowHeader
	flowsets []interface{}
}

func NewV9Decoder(r io.Reader) *V9Decoder {
	return &V9Decoder{
		Reader: r,
		Cache:  make(V9TemplateCache),
		header: new(V9FlowHeader),
	}
}

func (d *V9Decoder) ensureHeader() error {
	if d.header.Version == versionUnknown {
		return d.header.Unmarshal(d.Reader)
	}

	return nil
}

func (d *V9Decoder) ensureVersion() (err error) {
	if err = d.ensureHeader(); err == nil {
		if d.header.Version != 9 {
			err = errorIncompatibleVersion(d.header.Version, 9)
		}
	}
	return
}

func (d *V9Decoder) parseFlowSets() ([]interface{}, error) {
	flowsets := make([]interface{}, 0, d.header.Count)
	for i := uint16(0); i < d.header.Count; i++ {
		flowsets = flowsets[0 : i+1]
		var err error
		if flowsets[i], err = d.parseFlowSet(); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}

	return flowsets, nil
}

func (d *V9Decoder) parseFlowSet() (interface{}, error) {
	var header = new(V9FlowSetHeader)
	if err := header.Unmarshal(d.Reader); err != nil {
		return nil, err
	}

	log.Println("netflow: parse flow set:", header)
	size := int(header.Length) - 4
	if size < 4 {
		return nil, fmt.Errorf("error parsing flow set: can't parse %d bytes of data", size)
	}
	buf := make([]byte, size)
	if n, err := io.ReadFull(d.Reader, buf); err != nil {
		return nil, fmt.Errorf("error reading flow set, got %d bytes, wanted %d: %v", n, size, err.Error())
	}

	switch header.ID {
	case 0: // Template FlowSet
		//log.Printf("netflow: parse template flow set with id %d\n", header.ID)
		return parseV9TemplateFlowSet(header, bytes.NewBuffer(buf))
	case 1: // Options Template FlowSet
		//log.Printf("netflow: parse option template flow set with id %d\n", header.ID)
		return parseV9OptionsTemplateFlowSet(header, bytes.NewBuffer(buf))
	default: // Data FlowSet
		//log.Printf("netflow: parse data flow set with id %d\n", header.ID)
		return parseV9DataFlowSet(header, buf)
	}
}

func parseV9TemplateFlowSet(h *V9FlowSetHeader, buf *bytes.Buffer) (interface{}, error) {
	tfs := new(V9TemplateFlowSet)
	tfs.V9FlowSetHeader = *h
	return tfs, tfs.UnmarshalRecords(buf)
}

func parseV9OptionsTemplateFlowSet(h *V9FlowSetHeader, buf *bytes.Buffer) (interface{}, error) {
	ofs := new(V9OptionsTemplateFlowSet)
	ofs.V9FlowSetHeader = *h
	return ofs, ofs.UnmarshalRecords(buf)
}

func parseV9DataFlowSet(h *V9FlowSetHeader, data []byte) (interface{}, error) {
	dfs := new(V9DataFlowSet)
	dfs.V9FlowSetHeader = *h
	dfs.Data = data
	return dfs, nil
}

func (d *V9Decoder) Flows(flows chan FlowRecord) error {
	if err := d.ensureVersion(); err != nil {
		return err
	}

	log.Println("netflow: parsing", d.header)
	if d.flowsets == nil {
		var err error
		if d.flowsets, err = d.parseFlowSets(); err != nil {
			return err
		}
	}

	for _, flowset := range d.flowsets {
		log.Printf("netflow: parsing %T flow set\n", flowset)
		switch f := flowset.(type) {
		case nil:

		case *V9TemplateFlowSet:
			for _, r := range f.Records {
				// TODO(maze): expire templates with empty fields
				if d.Cache[r.TemplateID] == nil {
					log.Printf("netflow: new template with ID %d\n", r.TemplateID)
					d.Cache[r.TemplateID] = r
				}
			}

		case *V9DataFlowSet:
			if t, ok := d.Cache[f.ID]; ok {
				var records []V9FlowDataRecord
				var err error
				if records, err = t.DecodeFlowSet(f); err != nil {
					return err
				}
				for _, record := range records {
					record.Template = t
					flows <- &record
				}
			} else {
				log.Printf("netflow: no template with ID %d\n", f.ID)
			}
		}
	}

	return nil
}

func (d *V9Decoder) SampleInterval() int {
	return 1
}

func (d *V9Decoder) SetVersion(v uint16) error {
	if d.header.Version == versionUnknown {
		d.header.Version = v
		return d.header.Unmarshal(d.Reader)
	}

	d.header.Version = v
	return nil
}
