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
			if debug {
				debugLog.Println("failed to read flow set header:", err)
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
			ofs := OptionsTemplateFlowSet{}
			ofs.Header = header

			readSize := int(ofs.Header.Length) - ofs.Header.Len()
			if readSize < 4 {
				return io.ErrShortBuffer
			}
			data := make([]byte, readSize)
			if _, err := r.Read(data); err != nil {
				return err
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
			if _, err := r.Read(data); err != nil {
				return err
			}

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
				dfs.Bytes = data
				continue
			}
			s.RLock()
			tm, ok = s.GetTemplate(header.ID)
			s.RUnlock()
			if !ok {
				if debug {
					debugLog.Printf("no template for id=%d, storing %d raw bytes in data set\n", header.ID, len(data))
				}
				dfs.Bytes = data
				continue
			}
			if tr, ok = tm.(TemplateRecord); !ok {
				if debug {
					debugLog.Printf("no template record, got %T, storing %d raw bytes in data set\n", tm, len(data))
				}
				dfs.Bytes = data
				continue
			}
			if err := dfs.Unmarshal(bytes.NewBuffer(data), tr, t); err != nil {
				return err
			}
			records += uint16(len(dfs.Records))
			p.DataFlowSets = append(p.DataFlowSets, dfs)
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

func (tr TemplateRecord) register(s session.Session) {
	if s == nil {
		return
	}
	if debug {
		debugLog.Println("register template:", tr)
	}
	s.Lock()
	defer s.Unlock()
	s.AddTemplate(tr)
}

func (tr TemplateRecord) ID() uint16 {
	return tr.TemplateID
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
}

type DataFlowSet struct {
	Header  FlowSetHeader
	Records []DataRecord
	Bytes   []byte
}

func (dfs *DataFlowSet) Unmarshal(r io.Reader, tr TemplateRecord, t *Translate) error {
	buffer := new(bytes.Buffer)
	buffer.ReadFrom(r)

	dfs.Records = make([]DataRecord, 0)
	for buffer.Len() >= 4 { // Continue until only padding alignment bytes left
		var dr = DataRecord{}
		dr.TemplateID = tr.TemplateID
		if err := dr.Unmarshal(bytes.NewBuffer(buffer.Next(tr.Size())), tr.Fields, t); err != nil {
			return err
		}
		dfs.Records = append(dfs.Records, dr)
	}

	return nil
}

type DataRecord struct {
	TemplateID uint16
	Fields     Fields
}

func (dr *DataRecord) Unmarshal(r io.Reader, fss FieldSpecifiers, t *Translate) error {
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
			Type:   fss[i].Type,
			Length: fss[i].Length,
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

type Fields []Field
