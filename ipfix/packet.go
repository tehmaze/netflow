package ipfix

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tehmaze/netflow/read"
	"github.com/tehmaze/netflow/session"
)

// IPFIX

const (
	// Version word in the Message Header
	Version uint16 = 0x000a
	// EnterpriseBit used in the Field Specifier
	EnterpriseBit uint16 = 0x8000
	// VariableLength used in the Field Specifier
	VariableLength uint16 = 0xffff
)

// Message consists of a Message Header, followed by zero or more Sets. The Sets
// can be any of these three possible types: Data Set, Template Set, or Options
// Template Set.
//
// The format of the Message on the wire is:
//
//   +----------------------------------------------------+
//   | Message Header                                     |
//   +----------------------------------------------------+
//   | Set                                                |
//   +----------------------------------------------------+
//   | Set                                                |
//   +----------------------------------------------------+
//   ...
//   +----------------------------------------------------+
//   | Set                                                |
//   +----------------------------------------------------+
type Message struct {
	Header              MessageHeader
	TemplateSets        []TemplateSet
	OptionsTemplateSets []OptionsTemplateSet
	DataSets            []DataSet
}

// UnmarshalSets will, based on the Message length, unmarshal all sets in the
// message.
func (m *Message) UnmarshalSets(r io.Reader, s session.Session, t *Translate) error {
	// Read the rest of the message, containing the sets.
	data := make([]byte, int(m.Header.Length)-m.Header.Len())
	if _, err := r.Read(data); err != nil {
		return err
	}

	buffer := bytes.NewBuffer(data)
	for buffer.Len() > 0 {
		// Read the next set header
		header := SetHeader{}
		if err := header.Unmarshal(buffer); err != nil {
			return err
		}

		if debug {
			debugLog.Println("set header:", header)
		}

		if int(header.Length) < header.Len() {
			return io.ErrUnexpectedEOF
		}

		data := make([]byte, int(header.Length)-header.Len())
		if _, err := buffer.Read(data); err != nil {
			return err
		}

		if debug {
			debugLog.Printf("received set of %d bytes\n", len(data))
		}

		switch {
		case header.ID < 2: // Legacy header ID, should not happen.
			if debug {
				debugLog.Println("received legacy set id", header.ID)
			}
			return errProtocol("received invalid set id")

		case header.ID == 2: // Template set
			ts := TemplateSet{}
			ts.Header = header
			if err := ts.UnmarshalRecords(bytes.NewBuffer(data)); err != nil {
				return err
			}
			m.TemplateSets = append(m.TemplateSets, ts)

			for _, tr := range ts.Records {
				tr.register(m.Header.ObservationDomainID, s)
			}

		case header.ID == 3: // Options Template set
			ots := OptionsTemplateSet{}
			ots.Header = header
			if err := ots.UnmarshalRecords(bytes.NewBuffer(data)); err != nil {
				return err
			}
			m.OptionsTemplateSets = append(m.OptionsTemplateSets, ots)

		case header.ID >= 4 && header.ID <= 255:
			if debug {
				debugLog.Println("received reserved set id", header.ID)
			}
			// Silently dropped

		default:
			ds := DataSet{}
			ds.Header = header

			var (
				tm session.Template
				tr TemplateRecord
				ok bool
			)
			// If we don't have a session, or no template to resolve the Data
			// Set contained Data Records, we'll store the raw bytes in stead.
			if s == nil {
				if debug {
					debugLog.Printf("no session, storing %d raw bytes in data set\n", len(data))
				}
				ds.Bytes = data
				continue
			}
			if tm, ok = s.GetTemplate(m.Header.ObservationDomainID, header.ID); !ok {
				if debug {
					debugLog.Printf("no template for id=%d, storing %d raw bytes in data set\n", header.ID, len(data))
				}
				ds.Bytes = data
				continue
			}
			if tr, ok = tm.(TemplateRecord); !ok {
				if debug {
					debugLog.Printf("no template record, got %T, storing %d raw bytes in data set\n", tm, len(data))
				}
				ds.Bytes = data
				continue
			}
			if err := ds.Unmarshal(bytes.NewBuffer(data), tr, t); err != nil {
				return err
			}
			m.DataSets = append(m.DataSets, ds)
		}
	}

	return nil
}

// MessageHeader is a Message Header (RFC 7011 section 3.1)
//
// The format of the Message Header on the wire is:
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       Version Number          |            Length             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                           Export Time                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Sequence Number                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Observation Domain ID                      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type MessageHeader struct {
	Version             uint16
	Length              uint16
	ExportTime          uint32
	SequenceNumber      uint32
	ObservationDomainID uint32
}

// Len returns the length of the Message Header in bytes.
func (h *MessageHeader) Len() int {
	return 16
}

func (h *MessageHeader) String() string {
	return fmt.Sprintf("version=%d, length=%d, time=%s, seq=%d, odid=%d",
		h.Version, h.Length, time.Unix(int64(h.ExportTime), 0), h.SequenceNumber, h.ObservationDomainID)
}

// Unmarshal a message header from a reader.
func (h *MessageHeader) Unmarshal(r io.Reader) error {
	if err := read.Uint16(&h.Version, r); err != nil {
		return err
	}
	if err := read.Uint16(&h.Length, r); err != nil {
		return err
	}
	if err := read.Uint32(&h.ExportTime, r); err != nil {
		return err
	}
	if err := read.Uint32(&h.SequenceNumber, r); err != nil {
		return err
	}
	if err := read.Uint32(&h.ObservationDomainID, r); err != nil {
		return err
	}

	return nil
}

// FieldSpecifier is a Field Specifier (RFC 7011 section 3.2)
type FieldSpecifier struct {
	InformationElementID uint16
	Length               uint16
	EnterpriseNumber     uint32
	EnterpriseBitSet     bool
}

// IsEnterprise checks if the Enterprise bit (RFC RFC 7011 section 3.2) is set.
func (fs FieldSpecifier) IsEnterprise() bool {
	return fs.EnterpriseBitSet
}

// IsVariableLength ...
func (fs FieldSpecifier) IsVariableLength() bool {
	return fs.InformationElementID == VariableLength
}

func (fs FieldSpecifier) Len() int {
	if fs.EnterpriseBitSet {
		return 8
	}
	return 4
}

func (fs *FieldSpecifier) String() string {
	if fs.IsEnterprise() {
		return fmt.Sprintf("id=%d length=%d enterprise=%d", fs.InformationElementID, fs.Length, fs.EnterpriseNumber)
	}
	return fmt.Sprintf("id=%d length=%d", fs.InformationElementID, fs.Length)
}

func (fs *FieldSpecifier) Unmarshal(r io.Reader) error {
	if err := read.Uint16(&fs.InformationElementID, r); err != nil {
		if debug {
			debugLog.Println("error reading information element id", err)
		}
		return err
	}
	if err := read.Uint16(&fs.Length, r); err != nil {
		if debug {
			debugLog.Println("error reading length", err)
		}
		return err
	}
	// If the Enterprise bit is one, the Information Element identifier
	// identifies an enterprise-specific Information Element, and the Enterprise
	// Number field MUST be present.
	if fs.InformationElementID&EnterpriseBit > 0 {
		fs.EnterpriseBitSet = true
		fs.InformationElementID ^= EnterpriseBit
		if err := read.Uint32(&fs.EnterpriseNumber, r); err != nil {
			if debug {
				debugLog.Println("error reading enterprise number", err)
			}
			return err
		}
	}

	return nil
}

type FieldSpecifiers []FieldSpecifier

func (fs FieldSpecifiers) Len() int {
	var l = 0
	for _, f := range fs {
		l += f.Len()
	}
	return l
}

func (fs FieldSpecifiers) String() string {
	v := make([]string, len(fs))
	for i, f := range fs {
		v[i] = f.String()
	}
	return strings.Join(v, ",")
}

func (fs *FieldSpecifiers) Unmarshal(r io.Reader) error {
	for i := 0; i < len(*fs); i++ {
		if err := (*fs)[i].Unmarshal(r); err != nil {
			return err
		}
	}
	return nil
}

// SetHeader is a Set Header common to all three Set types (RFC 7011 section 3.3.2)
type SetHeader struct {
	// Identifies the Set. A value of 2 is reserved for Template Sets.
	// A value of 3 is reserved for Options Template Sets. Values from 4
	// to 255 are reserved for future use. Values 256 and above are used
	// for Data Sets. The Set ID values of 0 and 1 are not used, for
	// historical reasons [RFC3954].
	ID uint16
	// Total length of the Set, in octets, including the Set Header, all
	// records, and the optional padding. Because an individual Set MAY
	// contain multiple records, the Length value MUST be used to
	// determine the position of the next Set.
	Length uint16
}

func (h *SetHeader) Bytes() []byte {
	data := make([]byte, h.Len())
	binary.BigEndian.PutUint16(data[0:], h.ID)
	binary.BigEndian.PutUint16(data[2:], h.Length)
	return data
}

func (h SetHeader) Len() int {
	return 4
}

func (h SetHeader) String() string {
	switch {
	case h.ID == 0 || h.ID == 1:
		return fmt.Sprintf("id=%d (legacy, invalid) length=%d", h.ID, h.Length)
	case h.ID == 2:
		return fmt.Sprintf("id=%d (template set) length=%d", h.ID, h.Length)
	case h.ID == 3:
		return fmt.Sprintf("id=%d (options template set) length=%d", h.ID, h.Length)
	case h.ID >= 4 && h.ID <= 255:
		return fmt.Sprintf("id=%d (reserved future use) length=%d", h.ID, h.Length)
	default:
		return fmt.Sprintf("id=%d (data set) length=%d", h.ID, h.Length)
	}
}

func (h *SetHeader) Unmarshal(r io.Reader) error {
	if err := read.Uint16(&h.ID, r); err != nil {
		return err
	}
	if err := read.Uint16(&h.Length, r); err != nil {
		return err
	}

	return nil
}

// TemplateSet
type TemplateSet struct {
	Header  SetHeader
	Records []TemplateRecord
}

func (ts TemplateSet) Bytes() []byte {
	data := make([]byte, 0)
	data = append(data, ts.Header.Bytes()...)
	//data = append(data, ts.Records.Bytes()...)
	return data
}

func (ts TemplateSet) Len() int {
	return ts.Header.Len() // + ts.Records.Len()
}

func (ts TemplateSet) String() string {
	return fmt.Sprintf("%s (%s)", ts.Header, "") // ts.TemplateRecord)
}

func (ts *TemplateSet) UnmarshalRecords(r io.Reader) error {
	buffer := new(bytes.Buffer)
	if _, err := buffer.ReadFrom(r); err != nil {
		return err
	}

	// As long as there are more than 4 bytes in the buffer, we parse the next
	// TemplateRecord, otherwise it's padding.
	ts.Records = make([]TemplateRecord, 0)
	for buffer.Len() > 4 {
		record := TemplateRecord{}
		if err := record.Unmarshal(buffer); err != nil {
			return err
		}

		ts.Records = append(ts.Records, record)
	}

	return nil
}

type templateHeader struct {
	TemplateID uint16
	FieldCount uint16
}

// TemplateRecord contains any combination of IANA-assigned and/or enterprise-specific Information Element identifiers (RFC 7011 section 3.4.1)
type TemplateRecord struct {
	// Each Template Record is given a unique Template ID in the range
	// 256 to 65535.  This uniqueness is local to the Transport Session
	// and Observation Domain that generated the Template ID.  Since
	// Template IDs are used as Set IDs in the Sets they describe (see
	// RFC 7011 3.4.3), values 0-255 are reserved for special Set types
	// (e.g., Template Sets themselves), and Templates and Options
	// Templates (see RFC 7011 3.4.2) cannot share Template IDs within a
	// Transport Session and Observation Domain.  There are no
	// constraints regarding the order of the Template ID allocation.  As
	// Exporting Processes are free to allocate Template IDs as they see
	// fit, Collecting Processes MUST NOT assume incremental Template
	// IDs, or anything about the contents of a Template based on its
	// Template ID alone.
	TemplateID uint16
	// Number of fields in this Template Record.
	FieldCount uint16
	Fields     FieldSpecifiers
}

func (tr TemplateRecord) register(observationDomainID uint32, s session.Session) {
	if s == nil {
		return
	}
	if debug {
		debugLog.Println("register template:", tr)
	}
	s.Lock()
	defer s.Unlock()
	s.AddTemplate(observationDomainID, tr)
}

func (tr TemplateRecord) Bytes() []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:], tr.TemplateID)
	binary.BigEndian.PutUint16(data[2:], tr.FieldCount)
	return data
}

func (tr TemplateRecord) ID() uint16 {
	return tr.TemplateID
}

func (tr TemplateRecord) Len() int {
	return 4 + tr.Fields.Len()
}

func (tr TemplateRecord) String() string {
	return fmt.Sprintf("id=%d fields=%d (%s)", tr.TemplateID, tr.FieldCount, tr.Fields)
}

func (tr *TemplateRecord) Unmarshal(r io.Reader) error {
	if err := read.Uint16(&tr.TemplateID, r); err != nil {
		return err
	}
	if err := read.Uint16(&tr.FieldCount, r); err != nil {
		return err
	}

	tr.Fields = make(FieldSpecifiers, tr.FieldCount)
	if err := tr.Fields.Unmarshal(r); err != nil {
		return err
	}

	return nil
}

type OptionsTemplateSet struct {
	Header  SetHeader
	Records []OptionsTemplateRecord
}

func (ots OptionsTemplateSet) String() string {
	return fmt.Sprintf("%s (%d records)", ots.Header, len(ots.Records))
}

func (ots *OptionsTemplateSet) UnmarshalRecords(r io.Reader) error {
	buffer := new(bytes.Buffer)
	if _, err := buffer.ReadFrom(r); err != nil {
		return err
	}

	// As long as there are more than 4 bytes in the buffer, we parse the next
	// TemplateRecord, otherwise it's padding.
	ots.Records = make([]OptionsTemplateRecord, 0)
	for buffer.Len() > 4 {
		record := OptionsTemplateRecord{}
		if err := record.Unmarshal(buffer); err != nil {
			return err
		}

		ots.Records = append(ots.Records, record)
	}

	return nil
}

// OptionsTemplateRecord contains any combination of IANA-assigned and/or enterprise-specific Information Element identifiers (RFC 7011 section 3.4.2.2)
type OptionsTemplateRecord struct {
	// Each Options Template Record is given a unique Template ID in the
	// range 256 to 65535.
	TemplateID uint16

	// Number of all fields in this Options Template Record, including
	// the Scope Fields.
	FieldCount uint16
	Fields     FieldSpecifiers

	// Number of scope fields in this Options Template Record. The Scope
	// Fields are normal Fields, except that they are interpreted as
	// scope at the Collector. A scope field count of N specifies that
	// the first N Field Specifiers in the Template Record are Scope
	// Fields. The Scope Field Count MUST NOT be zero.
	ScopeFieldCount uint16
	ScopeFields     FieldSpecifiers
}

func (otr OptionsTemplateRecord) String() string {
	return fmt.Sprintf("id=%d fields=%d (%s) scope fields=%d (%s)",
		otr.TemplateID, otr.FieldCount, otr.Fields, otr.ScopeFieldCount, otr.ScopeFields)
}

func (otr *OptionsTemplateRecord) Unmarshal(r io.Reader) error {
	if err := read.Uint16(&otr.TemplateID, r); err != nil {
		return err
	}
	if err := read.Uint16(&otr.FieldCount, r); err != nil {
		return err
	}
	if err := read.Uint16(&otr.ScopeFieldCount, r); err != nil {
		return err
	}

	if otr.ScopeFieldCount > otr.FieldCount {
		return errProtocol(fmt.Sprintf("scope field count %d higher than field count %d", otr.ScopeFieldCount, otr.FieldCount))
	}

	buffer := new(bytes.Buffer)
	buffer.ReadFrom(r)
	if debug {
		hexdump(buffer.Bytes())
	}

	otr.ScopeFields = make(FieldSpecifiers, otr.ScopeFieldCount)
	if err := otr.ScopeFields.Unmarshal(buffer); err != nil {
		return err
	}

	otr.Fields = make(FieldSpecifiers, otr.FieldCount-otr.ScopeFieldCount)
	if err := otr.Fields.Unmarshal(buffer); err != nil {
		return err
	}

	return nil
}

type DataSet struct {
	Header  SetHeader
	Bytes   []byte
	Records []DataRecord
}

func (ds *DataSet) Unmarshal(r io.Reader, tr TemplateRecord, t *Translate) error {
	// We don't know how many records there are in a Data Set, so we'll keep
	// reading until we exhausted the buffer.
	buffer := new(bytes.Buffer)
	buffer.ReadFrom(r)

	ds.Records = make([]DataRecord, 0)
	for buffer.Len() > 0 {
		var dr = DataRecord{}
		dr.TemplateID = tr.TemplateID
		if err := dr.Unmarshal(buffer, tr.Fields, t); err != nil {
			// If we hit EOF, we've exhausted the buffer. The current DataRecord is discarded,
			// and we exit normally.
			if err == io.EOF {
				return nil
			} else {
				return err
			}
		}
		ds.Records = append(ds.Records, dr)
	}

	return nil
}

type DataRecord struct {
	TemplateID uint16
	Fields     Fields
}

func (dr *DataRecord) Unmarshal(r io.Reader, fss FieldSpecifiers, t *Translate) error {
	dr.Fields = make(Fields, 0)
	var err error
	for i := 0; i < len(fss); i++ {
		f := Field{}
		if err = f.Unmarshal(r, fss[i]); err != nil {
			return err
		}
		dr.Fields = append(dr.Fields, f)
	}

	if t != nil && len(dr.Fields) > 0 {
		if err := t.Record(dr, fss); err != nil {
			return err
		}
	}

	return nil
}

type Field struct {
	Bytes      []byte
	Translated *TranslatedField
}

func (f *Field) Unmarshal(r io.Reader, fs FieldSpecifier) error {
	if fs.Length == VariableLength {
		var err error
		f.Bytes, err = read.VariableLength(f.Bytes, r)
		return err
	} else {
		f.Bytes = make([]byte, fs.Length)
		_, err := r.Read(f.Bytes)
		return err
	}

}

type Fields []Field

func (fs Fields) Len() int {
	return len(fs)
}
