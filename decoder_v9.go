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
	Header   *V9FlowHeader
	flowsets []ExportRecord
	index    int
}

func NewV9Decoder(r io.Reader) (*V9Decoder, error) {
	d := &V9Decoder{
		Reader: r,
		Cache:  make(V9TemplateCache),
		Header: new(V9FlowHeader),
	}

	// First we decode the header
	if err := d.Header.Unmarshal(d.Reader); err != nil {
		return nil, err
	}

	// Next we decode the flowsets, which is required to determine the amount of
	// Export Records in this packet.
	var err error
	if d.flowsets, err = d.parseFlowSets(); err != nil {
		return nil, err
	}

	return d, nil
}

func (d *V9Decoder) parseFlowSets() ([]ExportRecord, error) {
	flowsets := make([]ExportRecord, 0, d.Header.Count)
	for i := uint16(0); i < d.Header.Count; i++ {
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

func (d *V9Decoder) parseFlowSet() (ExportRecord, error) {
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

func parseV9TemplateFlowSet(h *V9FlowSetHeader, buf *bytes.Buffer) (ExportRecord, error) {
	tfs := new(V9TemplateFlowSet)
	tfs.V9FlowSetHeader = *h
	return tfs, tfs.UnmarshalRecords(buf)
}

func parseV9OptionsTemplateFlowSet(h *V9FlowSetHeader, buf *bytes.Buffer) (ExportRecord, error) {
	ofs := new(V9OptionsTemplateFlowSet)
	ofs.V9FlowSetHeader = *h
	return ofs, ofs.UnmarshalRecords(buf)
}

func parseV9DataFlowSet(h *V9FlowSetHeader, data []byte) (ExportRecord, error) {
	dfs := new(V9DataFlowSet)
	dfs.V9FlowSetHeader = *h
	dfs.Data = data
	return dfs, nil
}

func (d *V9Decoder) Len() int {
	return len(d.flowsets)
}

func (d *V9Decoder) Next() (ExportRecord, error) {
	if d.index == len(d.flowsets) {
		return nil, io.EOF
	}

	flowset := d.flowsets[d.index]
	d.index++
	return flowset, nil
}

func (d *V9Decoder) SampleRate() int {
	return 1
}

func (d *V9Decoder) Version() uint16 {
	return Version9
}
