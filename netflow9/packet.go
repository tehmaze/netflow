package netflow9

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/tehmaze/netflow/read"
	"github.com/tehmaze/netflow/session"
)

const (
	// Version word in the Packet Header
	Version uint16 = 0x0009
)

// Packet consists of a Packet Header followed by one or more FlowSets. The
// FlowSets can be any of the possible three types: Template, Data, or Options
// Template.
//
// The format of the Packet on the wire is:
//
//   +--------+-------------------------------------------+
//   |        | +----------+ +---------+ +----------+     |
//   | Packet | | Template | | Data    | | Options  |     |
//   | Header | | FlowSet  | | FlowSet | | Template | ... |
//   |        | |          | |         | | FlowSet  |     |
//   |        | +----------+ +---------+ +----------+     |
//   +--------+-------------------------------------------+
type Packet struct {
	Header                  PacketHeader
	TemplateFlowSets        []TemplateFlowSet
	OptionsTemplateFlowSets []OptionsTemplateFlowSet
	DataFlowSets            []DataFlowSet
	OptionsDataFlowSets     []DataFlowSet
}

// PacketHeader is a Packet Header (RFC 3954 section 5.1)
type PacketHeader struct {
	Version        uint16
	Count          uint16
	SysUpTime      uint32
	UnixSecs       uint32
	SequenceNumber uint32
	SourceID       uint32
}

func (p *Packet) UnmarshalFlowSets(r io.Reader, s session.Session, t *Translate) error {
	if debug {
		debugLog.Printf("decoding %d flow sets, sequence number: %d\n", p.Header.Count, p.Header.SequenceNumber)
	}
	var records uint16 = 0

	for i := uint16(0); i < p.Header.Count; i++ {
		// We have all expected flows
		if records >= p.Header.Count {
			return nil
		}
		// Read the next set header
		header := FlowSetHeader{}
		if err := header.Unmarshal(r); err != nil {
			if(debug) {
				debugLog.Printf("failed to read flow set header %d/%d: %s\n", (i + 1), p.Header.Count, err)
			}
			return err
		}

		switch header.ID {
		case 0: // Template FlowSet
			tfs := TemplateFlowSet{}
			tfs.Header = header

			readSize := int(tfs.Header.Length) - tfs.Header.Len()
			if readSize < 4 {
				if debug {
					debugLog.Printf("short read size of %d\n", readSize)
				}
				return io.ErrShortBuffer
			}
			data := make([]byte, readSize)
			if _, err := r.Read(data); err != nil {
				if debug {
					debugLog.Printf("failed to read %d bytes: %v\n", readSize, err)
				}
				return err
			}

			if err := tfs.UnmarshalRecords(bytes.NewBuffer(data)); err != nil {
				return err
			}
			if debug {
				debugLog.Printf("unmarshaled %d records: %v\n", len(tfs.Records), tfs)
			}

			for _, tr := range tfs.Records {
				tr.register(s)
			}

			records += 1
			p.TemplateFlowSets = append(p.TemplateFlowSets, tfs)

		case 1: // Options Template FlowSet
			var err error
			ofs := OptionsTemplateFlowSet{}
			ofs.Header = header

			readSize := int(ofs.Header.Length) - ofs.Header.Len()
			if(readSize < 4) {
				debugLog.Printf("ofs: short read size of %d\n", readSize)
				return io.ErrShortBuffer
			}

			data := make([]byte, readSize)
			_, err = r.Read(data)
			if(err != nil) {
				debugLog.Printf("ofs: failed to read %d bytes: %v\n", readSize, err)
				return err
			}

			err = ofs.UnmarshalRecords(bytes.NewBuffer(data))
			if(err != nil) {
				return err
			}

			if(debug) {
				debugLog.Printf("ofs: unmarshaled %d records: %v\n", len(ofs.Records), ofs)
			}

			for _, record := range ofs.Records {
				record.register(s)
			}

			records += 1
			p.OptionsTemplateFlowSets = append(p.OptionsTemplateFlowSets, ofs)

		default:
			dfs := DataFlowSet{}
			dfs.Header = header

			if dfs.Header.Length < 4 {
				return io.ErrShortBuffer
			}
			data := make([]byte, int(dfs.Header.Length)-dfs.Header.Len())
			if(debug) {
				debugLog.Printf("Reading %d bytes for DataFlowSet\n", len(data))
			}
			if _, err := r.Read(data); err != nil {
				return err
			}

			var (
				tm session.Template
				ok bool
			)
			// If we don't have a session, or no template to resolve the Data
			// Set contained Data Records, we'll store the raw bytes in stead.
			if s == nil {
				if debug {
					debugLog.Printf("no session, storing %d raw bytes in data set\n", len(data))
				}
				dfs.Bytes = data
				continue
			}
			tm, ok = s.GetTemplate(header.ID)
			if !ok {
				if(debug) {
					debugLog.Printf("no template for id=%d, storing %d raw bytes in data set\n", header.ID, len(data))
				}
				dfs.Bytes = data
				continue
			}
			err := dfs.Unmarshal(bytes.NewBuffer(data), tm, t)
			if(err != nil) {
				debugLog.Printf("Failed to unmarshal DataFlowSet: %s\n", err)
				return err
			}
			records += uint16(len(dfs.Records))
			switch tm.(type) {
				case *TemplateRecord:
					p.DataFlowSets = append(p.DataFlowSets, dfs)
				case *OptionTemplateRecord:
					if(debug) {
						debugLog.Printf("v9 data record with option template: %v\n", tm)
					}
					for _, record := range dfs.Records {
						if(debug) {
							debugLog.Printf("v9 option data record: %v\n", record)
						}
						for _, scope := range record.OptionScopes {
							for _, field := range record.Fields {
								s.SetOption(0, field.Type, &session.Option{
									TemplateID: header.ID,
									Scope: scope,
									Bytes: field.Bytes,
									EnterpriseNumber: 0,
									Type: field.Type,
									Value: field.Translated.Value,
								})
							}
						}
					}
					p.OptionsDataFlowSets = append(p.OptionsDataFlowSets, dfs)
			}
		}
	}

	return nil
}

func (h PacketHeader) Len() int {
	return 20
}

func (h *PacketHeader) Unmarshal(r io.Reader) error {
	if err := read.Uint16(&h.Version, r); err != nil {
		return err
	}
	if err := read.Uint16(&h.Count, r); err != nil {
		return err
	}
	if err := read.Uint32(&h.SysUpTime, r); err != nil {
		return err
	}
	if err := read.Uint32(&h.UnixSecs, r); err != nil {
		return err
	}
	if err := read.Uint32(&h.SequenceNumber, r); err != nil {
		return err
	}
	if err := read.Uint32(&h.SourceID, r); err != nil {
		return err
	}

	return nil
}

type FlowSetHeader struct {
	ID     uint16
	Length uint16
}

func (h *FlowSetHeader) Len() int {
	return 4
}

func (h *FlowSetHeader) Unmarshal(r io.Reader) error {
	if err := read.Uint16(&h.ID, r); err != nil {
		return err
	}
	if err := read.Uint16(&h.Length, r); err != nil {
		return err
	}

	return nil
}

// TemplateFlowSet enhance the flexibility of the Flow Record format because
// they allow the NetFlow Collector to process Flow Records without necessarily
// knowing the interpretation of all the data in the Flow Record.
//
// The format of the Template FlowSet is as follows:
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       FlowSet ID = 0          |          Length               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |      Template ID 256          |         Field Count           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Field Type 1           |         Field Length 1        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Field Type 2           |         Field Length 2        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |             ...               |              ...              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Field Type N           |         Field Length N        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |      Template ID 257          |         Field Count           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Field Type 1           |         Field Length 1        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Field Type 2           |         Field Length 2        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |             ...               |              ...              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Field Type M           |         Field Length M        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |             ...               |              ...              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Template ID K          |         Field Count           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |             ...               |              ...              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type TemplateFlowSet struct {
	Header  FlowSetHeader
	Records []TemplateRecord
}

func (tfs *TemplateFlowSet) UnmarshalRecords(r io.Reader) error {
	buffer := new(bytes.Buffer)
	if _, err := buffer.ReadFrom(r); err != nil {
		return err
	}

	// As long as there are more than 4 bytes in the buffer, we parse the next
	// TemplateRecord, otherwise it's padding.
	tfs.Records = make([]TemplateRecord, 0)
	for buffer.Len() > 4 {
		record := TemplateRecord{}
		if err := record.Unmarshal(buffer); err != nil {
			return err
		}

		tfs.Records = append(tfs.Records, record)
	}

	return nil
}

// TemplateRecord is a Template Record as per RFC3964 section 5.2
type TemplateRecord struct {
	TemplateID uint16
	FieldCount uint16
	Fields     FieldSpecifiers
}

func (tr *TemplateRecord) register(s session.Session) {
	if s == nil {
		return
	}
	if debug {
		debugLog.Println("register template:", tr)
	}
	s.AddTemplate(tr)
}

func (tr TemplateRecord) ID() uint16 {
	return tr.TemplateID
}

func (this TemplateRecord) GetFields() []session.TemplateFieldSpecifier {
	fs := make([]session.TemplateFieldSpecifier, len(this.Fields))
	for i, v := range this.Fields {
		fs[i] = v
	}
	return fs
}

func (tr TemplateRecord) String() string {
	return fmt.Sprintf("id=%d fields=%d (%s)", tr.TemplateID, tr.FieldCount, tr.Fields)
}

func (tr TemplateRecord) Size() int {
	var size int
	for _, f := range tr.Fields {
		size += int(f.Length)
	}
	return size
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

type FieldSpecifier struct {
	Type   uint16
	Length uint16
}

func (fs *FieldSpecifier) String() string {
	return fmt.Sprintf("type=%d length=%d", fs.Type, fs.Length)
}

func (f *FieldSpecifier) Unmarshal(r io.Reader) error {
	if err := read.Uint16(&f.Type, r); err != nil {
		return err
	}
	if err := read.Uint16(&f.Length, r); err != nil {
		return err
	}

	return nil
}

func (this FieldSpecifier) GetType() uint16 {
	return this.Type
}

func (this FieldSpecifier) GetLength() uint16 {
	return this.Length
}

type FieldSpecifiers []FieldSpecifier

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

// OptionsTemplateRecord (and its corresponding OptionsDataRecord) is used to
// supply information about the NetFlow process configuration or NetFlow
// process specific data, rather than supplying information about IP Flows.
//
// For example, the Options Template FlowSet can report the sample rate
// of a specific interface, if sampling is supported, along with the
// sampling method used.
//
// The format of the Options Template FlowSet follows:
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       FlowSet ID = 1          |          Length               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Template ID           |      Option Scope Length      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Option Length          |       Scope 1 Field Type      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Scope 1 Field Length      |               ...             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Scope N Field Length      |      Option 1 Field Type      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Option 1 Field Length     |             ...               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Option M Field Length     |           Padding             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type OptionsTemplateFlowSet struct {
	Header FlowSetHeader
	Records []OptionTemplateRecord
	Bytes []byte
}

func (this *OptionsTemplateFlowSet) UnmarshalRecords(r io.Reader) error {
	buffer := new(bytes.Buffer)
	if _, err := buffer.ReadFrom(r); err != nil {
		return err
	}

	// As long as there are more than 4 bytes in the buffer, we parse the next
	// TemplateRecord, otherwise it's padding.
	this.Records = make([]OptionTemplateRecord, 0)
	for buffer.Len() > 4 {
		record := OptionTemplateRecord{}
		if err := record.Unmarshal(buffer); err != nil {
			return err
		}

		this.Records = append(this.Records, record)
	}

	return nil
}

type OptionTemplateRecord struct {
	TemplateID    uint16
	ScopeLength   uint16
	OptionsLength uint16
	Scopes        ScopeSpecifiers
	Options       FieldSpecifiers
}

func (this *OptionTemplateRecord) register(s session.Session) {
	if(s == nil) {
		return
	}
	if(debug) {
		debugLog.Println("register option template:", this)
	}
	s.AddTemplate(this)
}

func (this OptionTemplateRecord) ID() uint16 {
	return this.TemplateID
}

func (this OptionTemplateRecord) GetFields() []session.TemplateFieldSpecifier {
	l := len(this.Options)
	fs := make([]session.TemplateFieldSpecifier, l)
	for i, v := range this.Options {
		fs[i] = v
	}
	return fs
}

func (this OptionTemplateRecord) Size() int {
	var size int
	for _, scope := range this.Scopes {
		size += int(scope.Length)
	}
	for _, option := range this.Options {
		size += int(option.Length)
	}
	return size
}

func (this *OptionTemplateRecord) Unmarshal(r io.Reader) error {
	var err error

	err = read.Uint16(&this.TemplateID, r)
	if(err != nil) {
		return err
	}

	err = read.Uint16(&this.ScopeLength, r)
	if(err != nil) {
		return err
	}

	err = read.Uint16(&this.OptionsLength, r)
	if(err != nil) {
		return err
	}

	this.Scopes = make(ScopeSpecifiers, this.ScopeLength / 4)
	err = this.Scopes.Unmarshal(r)
	if(err != nil) {
		return err
	}

	this.Options = make(FieldSpecifiers, this.OptionsLength / 4)
	err = this.Options.Unmarshal(r)
	if(err != nil) {
		return err
	}

	return nil
}

type ScopeSpecifier struct {
	Type   uint16
	Length uint16
}

func (this *ScopeSpecifier) String() string {
	return fmt.Sprintf("type=%d length=%d", this.Type, this.Length)
}

func (this *ScopeSpecifier) Unmarshal(r io.Reader) error {
	if err := read.Uint16(&this.Type, r); err != nil {
		return err
	}
	if err := read.Uint16(&this.Length, r); err != nil {
		return err
	}

	return nil
}

func (this ScopeSpecifier) GetType() uint16 {
	return this.Type
}

func (this ScopeSpecifier) GetLength() uint16 {
	return this.Length
}

type ScopeSpecifiers []ScopeSpecifier

func (this ScopeSpecifiers) String() string {
	v := make([]string, len(this))
	for i, scope := range this {
		v[i] = scope.String()
	}
	return strings.Join(v, ",")
}

func (this *ScopeSpecifiers) Unmarshal(r io.Reader) error {
	for i := 0; i < len(*this); i++ {
		if err := (*this)[i].Unmarshal(r); err != nil {
			return err
		}
	}
	return nil
}

type DataFlowSet struct {
	Header  FlowSetHeader
	Records []DataRecord
	Bytes   []byte
}

func (dfs *DataFlowSet) Unmarshal(r io.Reader, template session.Template, t *Translate) error {
	buffer := new(bytes.Buffer)
	buffer.ReadFrom(r)

	dfs.Records = make([]DataRecord, 0)
	for buffer.Len() >= 4 { // Continue until only padding alignment bytes left
		var dr = DataRecord{}
		dr.TemplateID = template.ID()
		if err := dr.Unmarshal(bytes.NewBuffer(buffer.Next(template.Size())), template.GetFields(), t); err != nil {
			return err
		}
		dfs.Records = append(dfs.Records, dr)
	}

	return nil
}

type DataRecord struct {
	TemplateID   uint16
	OptionScopes []session.OptionScope
	Fields       Fields
}

func (dr *DataRecord) Unmarshal(r io.Reader, fss []session.TemplateFieldSpecifier, t *Translate) error {
	// We don't know how many records there are in a Data Set, so we'll keep
	// reading until we exhausted the buffer.
	buffer := new(bytes.Buffer)
	if _, err := buffer.ReadFrom(r); err != nil {
		return err
	}

	dr.Fields = make(Fields, 0)
	var err error
	for i := 0; buffer.Len() > 0 && i < len(fss); i++ {
		f := Field{
			Type:   fss[i].GetType(),
			Length: fss[i].GetLength(),
		}
		if err = f.Unmarshal(buffer); err != nil {
			return err
		}
		dr.Fields = append(dr.Fields, f)
	}

	if t != nil && len(dr.Fields) > 0 {
		if err := t.Record(dr); err != nil {
			return err
		}
	}

	return nil
}

func (this *DataRecord) GetTemplateID() uint16 {
	return this.TemplateID
}

func (this *DataRecord) GetScopes() []session.OptionScope {
	return this.OptionScopes
}

func (this *DataRecord) GetFields() Fields {
	return this.Fields
}

type Field struct {
	Type       uint16
	Length     uint16
	Translated *TranslatedField
	Bytes      []byte
}

func (f *Field) Unmarshal(r io.Reader) error {
	f.Bytes = make([]byte, f.Length)
	if _, err := r.Read(f.Bytes); err != nil {
		return err
	}

	return nil
}

func (this *Field) GetType() uint16 {
	return this.Type
}

func (this *Field) GetLength() uint16 {
	return this.Length
}

func (this *Field) GetTranslated() *TranslatedField {
	return this.Translated
}

func (this *Field) GetBytes() []byte {
	return this.Bytes
}

type Fields []Field
