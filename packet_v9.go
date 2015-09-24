package netflow

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"time"
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

func (h *V9FlowHeader) String() string {
	return fmt.Sprintf("version=%d, count=%d, uptime=%s, time=%s, seq=%d, id=%d",
		h.Version, h.Count, time.Duration(h.SysUptime)*time.Second, time.Unix(int64(h.UnixTime), 0), h.Sequence, h.SourceID)
}

func (h *V9FlowHeader) Unmarshal(r io.Reader) error {
	if h.Version == 0 {
		log.Println("netflow: unmarshal full v9 header")
		var err error
		if h.Version, err = readUint16(r); err != nil {
			return err
		}
	}
	log.Println("netflow: unmarshal v9 header")
	return h.unmarshalAfterHeader(r)
}

func (h *V9FlowHeader) unmarshalAfterHeader(r io.Reader) (err error) {
	if h.Count, err = readUint16(r); err != nil {
		return
	}
	if h.SysUptime, err = readUint32(r); err != nil {
		return
	}
	if h.UnixTime, err = readUint32(r); err != nil {
		return
	}
	if h.Sequence, err = readUint32(r); err != nil {
		return
	}
	if h.SourceID, err = readUint32(r); err != nil {
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

func (h *V9FlowSetHeader) String() string {
	return fmt.Sprintf("id=%d, length=%d", h.ID, h.Length)
}

func (h *V9FlowSetHeader) Unmarshal(r io.Reader) error {
	var err error
	if h.ID, err = readUint16(r); err != nil {
		return err
	}
	if h.Length, err = readUint16(r); err != nil {
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return err
	}

	return nil
}

// V9TemplateFlowSet is one or more Template Records that have been grouped together in an Export Packet.
type V9TemplateFlowSet struct {
	V9FlowSetHeader
	Records []*V9TemplateRecord
}

func (tfs *V9TemplateFlowSet) Bytes() []byte {
	return structPack(tfs)
}

func (tfs *V9TemplateFlowSet) Len() int {
	return structLen(tfs)
}

// UnmarshalRecords can be called after the V9FlowSetHeader is read and will read the Template Records.
func (tfs *V9TemplateFlowSet) UnmarshalRecords(buf *bytes.Buffer) error {
	tfs.Records = make([]*V9TemplateRecord, 0)

	for buf.Len() >= 4 {
		t := new(V9TemplateRecord)
		if err := t.Unmarshal(buf); err != nil {
			return err
		}
		tfs.Records = append(tfs.Records, t)
	}

	return nil
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

func (tr *V9TemplateRecord) Bytes() []byte {
	return structPack(tr)
}

func (tr *V9TemplateRecord) DecodeFlowSet(dfs *V9DataFlowSet) ([]V9FlowDataRecord, error) {
	if dfs.ID != tr.TemplateID {
		return nil, fmt.Errorf("invalid template ID, expected %d, got %d", tr.TemplateID, dfs.ID)
	}

	var (
		r   = V9FlowDataRecord{}
		rs  = make([]V9FlowDataRecord, 0)
		buf = bytes.NewBuffer(dfs.Data)
	)

	// It's fine to leave up to 3 bytes in the buffer, as we must support padding
	for buf.Len() >= 4 {
		r.Values = parseV9FieldValues(buf, tr.Fields)
		rs = append(rs, r)
	}

	return rs, nil
}

func (tr *V9TemplateRecord) Len() int {
	return structLen(tr)
}

func (tr *V9TemplateRecord) String() string {
	return fmt.Sprintf("template id=%d, fields=%d", tr.TemplateID, tr.FieldCount)
}

func (tr *V9TemplateRecord) Unmarshal(buf *bytes.Buffer) error {
	var err error
	if tr.TemplateID, err = readUint16(buf); err != nil {
		return err
	}
	if tr.FieldCount, err = readUint16(buf); err != nil {
		return err
	}

	readSize := int(tr.FieldCount) * 4
	if readSize > buf.Len() {
		return fmt.Errorf("error parsing template record, need %d bytes, got %d", readSize, buf.Len())
	}

	tr.Fields = make(V9Fields, tr.FieldCount)
	return tr.Fields.UnmarshalAll(buf)
}

// V9Field contains a type and a length.
type V9Field struct {
	// A numeric value that represents the type of field.
	Type uint16

	// The length (in bytes) of the field.
	Length uint16
}

func (f *V9Field) String() string {
	if t, ok := v9fieldType[f.Type]; ok {
		return fmt.Sprintf("%s (%d bytes)", t.Name, f.Length)
	}
	return fmt.Sprintf("%d (%d bytes)", f.Type, f.Length)
}

func (f *V9Field) Unmarshal(r io.Reader) (err error) {
	if f.Type, err = readUint16(r); err != nil {
		return
	}
	if f.Length, err = readUint16(r); err != nil {
		return
	}
	return
}

type V9Fields []V9Field

func (fs V9Fields) String() string {
	v := make([]string, len(fs))
	for i, f := range fs {
		v[i] = f.String()
	}
	return strings.Join(v, ",")
}

func (fs V9Fields) UnmarshalAll(r io.Reader) (err error) {
	for i := 0; i < len(fs); i++ {
		if err = fs[i].Unmarshal(r); err != nil {
			return
		}
	}
	return
}

// V9FlowDataRecord provides information about an IP Flow observed at an Observation Point.
type V9FlowDataRecord struct {
	// List of Flow Data Record values stored in raw format as []byte
	Values [][]byte
}

func (r V9FlowDataRecord) Map(tr *V9TemplateRecord) map[string]interface{} {
	m := map[string]interface{}{}
	for i, value := range r.Values {
		f := tr.Fields[i]
		if t, ok := v9fieldType[f.Type]; ok {
			m[t.Name] = t.Value(value)
		} else {
			m[strconv.Itoa(int(f.Type))] = value
		}
	}
	return m
}

func (r *V9FlowDataRecord) Bytes() []byte {
	return structPack(r)
}

func (r *V9FlowDataRecord) Len() int {
	return structLen(r)
}

/*
func (r *V9FlowDataRecord) String() string {
	m := r.Map()
	if _, ok := m["IPV6_SRC_ADDR"]; ok {
		return fmt.Sprintf("%s/%d:%d -> %s/%d:%d",
			m["IPV6_SRC_ADDR"], m["SRC_MASK"], m["L4_SRC_PORT"],
			m["IPV6_DST_ADDR"], m["DST_MASK"], m["L4_DST_PORT"])
	}
	return fmt.Sprintf("%s/%d:%d -> %s/%d:%d",
		m["IPV4_SRC_ADDR"], m["SRC_MASK"], m["L4_SRC_PORT"],
		m["IPV4_DST_ADDR"], m["DST_MASK"], m["L4_DST_PORT"])
}
*/

// V9DataFlowSet is one or more records, of the same type, that are grouped together in an Export Packet.
type V9DataFlowSet struct {
	V9FlowSetHeader
	Data []byte
}

func (dfs *V9DataFlowSet) Bytes() []byte {
	return structPack(dfs)
}

func (dfs *V9DataFlowSet) Len() int {
	return structLen(dfs)
}

// V9OptionsTemplateFlowSet is one or more Options Template Records that have been grouped together in an Export Packet.
type V9OptionsTemplateFlowSet struct {
	V9FlowSetHeader

	// List of Options Template Records
	Records []*V9OptionsTemplateRecord
}

func (ofs *V9OptionsTemplateFlowSet) Bytes() []byte {
	return structPack(ofs)
}

func (ofs *V9OptionsTemplateFlowSet) Len() int {
	return structLen(ofs)
}

func (ofs *V9OptionsTemplateFlowSet) UnmarshalRecords(buf *bytes.Buffer) (err error) {
	ofs.Records = make([]*V9OptionsTemplateRecord, 0)
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

func (otr *V9OptionsTemplateRecord) Unmarshal(r io.Reader) (err error) {
	if otr.TemplateID, err = readUint16(r); err != nil {
		return
	}
	if otr.ScopeLength, err = readUint16(r); err != nil {
		return
	}
	if otr.OptionLength, err = readUint16(r); err != nil {
		return
	}

	otr.Scopes = make(V9Fields, otr.ScopeLength)
	if err = otr.Scopes.UnmarshalAll(r); err != nil {
		return
	}

	otr.Options = make(V9Fields, otr.OptionLength)
	if err = otr.Options.UnmarshalAll(r); err != nil {
		return
	}

	return
}

func parseV9FieldValues(buf *bytes.Buffer, fields V9Fields) [][]byte {
	values := make([][]byte, len(fields))
	for i, f := range fields {
		if buf.Len() < int(f.Length) {
			return nil
		}
		values[i] = buf.Next(int(f.Length))
	}
	return values
}
