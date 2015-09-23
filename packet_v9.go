package netflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// V9FlowHeader is a Flow Header (RFC 3954 section 5.1)
type V9FlowHeader struct {
	Header
	Count     uint16
	SysUptime uint32
	UnixTime  uint32
	Sequence  uint32
	SourceID  uint32
}

func (h V9FlowHeader) Read(r io.Reader) (err error) {
	if h.Version == 0 {
		if err = binary.Read(r, binary.BigEndian, &h); err != nil {
			return
		}
	}
	return h.readAfterHeader(r)
}

func (h V9FlowHeader) readAfterHeader(r io.Reader) (err error) {
	if err = binary.Read(r, binary.BigEndian, &h.Count); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &h.SysUptime); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &h.UnixTime); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &h.Sequence); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &h.SourceID); err != nil {
		return
	}
	return
}

// V9FlowSetHeader is a common header for V9TemplateFlowSet and V9DataFlowSet (RFC 3954 section 5.2 & 5.3)
type V9FlowSetHeader struct {
	// ID can mean different things:
	//    0 for TemplateFlowSet
	//    1 for OptionsTemplateFlowSet
	//    256-65535 for DataFlowSet (used as TemplateID)
	ID     uint16
	Length uint16
}

func (h *V9FlowSetHeader) Read(r io.Reader) (err error) {
	if err = binary.Read(r, binary.BigEndian, &h.ID); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &h.Length); err != nil {
		return
	}
	return
}

// V9TemplateFlowSet is one or more Template Records that have been grouped together in an Export Packet.
type V9TemplateFlowSet struct {
	V9FlowSetHeader
	Records []*V9TemplateRecord
}

// ReadRecords can be called after teh V9FlowSetHeader is read and will read the Template Records.
func (tfs *V9TemplateFlowSet) ReadRecords(r io.Reader) (err error) {
	tfs.Records = make([]*V9TemplateRecord, 0)
	for {
		tr := new(V9TemplateRecord)
		if err = tr.Read(r); err != nil {
			if err == io.EOF {
				break
			}
			return
		}

		tfs.Records = append(tfs.Records, tr)
	}

	return
}

// V9TemplateRecord defines the structure and interpretation of fields in a Flow Data Record.
type V9TemplateRecord struct {
	// Each of the newly generated Template Records is given a unique
	// Template ID. This uniqueness is local to the Observation Domain that
	// generated the Template ID. Template IDs of Data FlowSets are numbered
	// from 256 to 65535.
	TemplateID uint16

	// Number of fields in this Template Record. Because a Template FlowSet
	// usually contains multiple Template Records, this field allows the
	// Collector to determine the end of the current Template Record and
	// the start of the next.
	FieldCount uint16

	// List of fields in this Template Record.
	Fields V9Fields
}

func (tr *V9TemplateRecord) DecodeFlowSet(dfs *V9DataFlowSet) (rs []V9FlowDataRecord, err error) {
	if dfs.ID != tr.TemplateID {
		err = fmt.Errorf("invalid template ID, expected %d, got %d", tr.TemplateID, dfs.ID)
		return
	}

	buf := bytes.NewBuffer(dfs.Data)

parser:
	// It's fine to leave up to 3 bytes in the buffer, as we must support padding
	for buf.Len() >= 4 {
		r := V9FlowDataRecord{}
		r.Values = make([][]byte, tr.FieldCount)
		for i, f := range tr.Fields {
			if buf.Len() < int(f.Length) {
				// If we have a short read, stop parsing
				break parser
			}
			r.Values[i] = buf.Next(int(f.Length))
		}

		rs = append(rs, r)
	}

	return
}

func (tr *V9TemplateRecord) Read(r io.Reader) (err error) {
	if err = binary.Read(r, binary.BigEndian, &tr.TemplateID); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &tr.FieldCount); err != nil {
		return
	}

	tr.Fields = make([]V9Field, tr.FieldCount)
	if err = tr.Fields.ReadAll(r); err != nil {
		return
	}

	return
}

// V9Field contains a type and a length.
type V9Field struct {
	// A numeric value that represents the type of field.
	Type uint16

	// The length (in bytes) of the field.
	Length uint16
}

func (f *V9Field) Read(r io.Reader) (err error) {
	return binary.Read(r, binary.BigEndian, f)
}

type V9Fields []V9Field

func (fs V9Fields) ReadAll(r io.Reader) (err error) {
	for i := 0; i < len(fs); i++ {
		if err = fs[i].Read(r); err != nil {
			return
		}
	}
	return
}

// V9FlowDataRecord  provides information about an IP Flow observed at an Observation Point.
type V9FlowDataRecord struct {
	// List of Flow Data Record values stored in raw format as []byte
	Values [][]byte
}

// V9DataFlowSet is one or more records, of the same type, that are grouped together in an Export Packet.
type V9DataFlowSet struct {
	V9FlowSetHeader
	Data []byte
}

// ReadData can be called after the V9FlowSetHeader is read and will read the Data Flow Set data.
func (dfs *V9DataFlowSet) ReadData(r io.Reader) (err error) {
	dfs.Data = make([]byte, dfs.Length)
	_, err = r.Read(dfs.Data)
	return
}

// V9OptionsTemplateFlowSet is one or more Options Template Records that have been grouped together in an Export Packet.
type V9OptionsTemplateFlowSet struct {
	V9FlowSetHeader

	// List of Options Template Records
	Records []*V9OptionsTemplateRecord
}

func (ofs *V9OptionsTemplateFlowSet) ReadRecords(r io.Reader) (err error) {
	ofs.Records = make([]*V9OptionsTemplateRecord, 0)
	for {
		tr := new(V9OptionsTemplateRecord)
		if err = tr.Read(r); err != nil {
			if err == io.EOF {
				break
			}
			return
		}

		ofs.Records = append(ofs.Records, tr)
	}

	return
}

// V9OptionsTemplateRecord defines the structure and interpretation of fields in
// an Options Data Record, including defining the scope within which the Options
// Data Record is relevant.
type V9OptionsTemplateRecord struct {
	// Template ID of this Options Template. This value is greater than 255.
	TemplateID uint16

	// The length in bytes of all Scope field definitions contained in this
	// Options Template Record.
	ScopeLength uint16

	// The length (in bytes) of all options field definitions contained in
	// this Options Template Record.
	OptionLength uint16

	// List of Scope fields in this Options Template Record.
	Scopes V9Fields

	// List of Option fields in this Options Template Record.
	Options V9Fields
}

func (otr *V9OptionsTemplateRecord) Read(r io.Reader) (err error) {
	if err = binary.Read(r, binary.BigEndian, &otr.TemplateID); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &otr.ScopeLength); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &otr.OptionLength); err != nil {
		return
	}

	otr.Scopes = make(V9Fields, otr.ScopeLength)
	if err = otr.Scopes.ReadAll(r); err != nil {
		return
	}

	otr.Options = make(V9Fields, otr.OptionLength)
	if err = otr.Options.ReadAll(r); err != nil {
		return
	}

	return
}
