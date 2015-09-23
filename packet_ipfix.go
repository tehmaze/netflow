package netflow

import (
	"fmt"
	"io"
	"log"
	"time"
)

// IPFIX

const (
	IPFIXEnterpriseBit uint16 = 1 << 15
)

// IPFIXMessageHeader is a Message Header (RFC 7011 section 3.1)
type IPFIXMessageHeader struct {
	Header
	Length              uint16
	ExportTime          uint32
	SequenceNumber      uint32
	ObservationDomainID uint32
}

func (h *IPFIXMessageHeader) String() string {
	return fmt.Sprintf("version=%d, length=%d, time=%s, seq=%d, odid=%d",
		h.Version, h.Length, time.Unix(int64(h.ExportTime), 0), h.SequenceNumber, h.ObservationDomainID)
}

func (h *IPFIXMessageHeader) Unmarshal(r io.Reader) error {
	if h.Version == 0 {
		log.Println("ipfix: unmarshal full header")
		var err error
		if h.Version, err = readUint16(r); err != nil {
			return err
		}
	}
	log.Println("ipfix: unmarshal header")
	return h.unmarshalAfterHeader(r)
}

func (h *IPFIXMessageHeader) unmarshalAfterHeader(r io.Reader) error {
	var err error
	if h.Length, err = readUint16(r); err != nil {
		return err
	}
	if h.ExportTime, err = readUint32(r); err != nil {
		return err
	}
	if h.SequenceNumber, err = readUint32(r); err != nil {
		return err
	}
	if h.ObservationDomainID, err = readUint32(r); err != nil {
		return err
	}
	return nil
}

// IPFIXFieldSpecifier is a Field Specifier (RFC 7011 section 3.2)
type IPFIXFieldSpecifier struct {
	InformationElement uint16
	Length             uint16
	EnterpriseNumber   uint32
}

func (fs IPFIXFieldSpecifier) IsEnterprise() bool {
	return fs.InformationElement&IPFIXEnterpriseBit > 0
}

// IPFIXSetHeader is a Set Header common to all three Set types (RFC 7011 section 3.3.2)
type IPFIXSetHeader struct {
	ID     uint16
	Length uint16
}

// IPFIXTemplateRecord contains any combination of IANA-assigned and/or enterprise-specific Information Element identifiers (RFC 7011 section 3.4.1)
type IPFIXTemplateRecord struct {
	TemplateID uint16 // 256-65535
	FieldCount uint16
	Fields     IPFIXFields
}

type IPFIXField struct {
}

type IPFIXFields []IPFIXField

// IPFIXOptionsTemplateRecord contains any combination of IANA-assigned and/or enterprise-specific Information Element identifiers (RFC 7011 section 3.4.2.2)
type IPFIXOptionsTemplateRecord struct {
	// Each Options Template Record is given a unique Template ID in the
	// range 256 to 65535.
	TemplateID uint16

	// Number of all fields in this Options Template Record, including
	// the Scope Fields.
	FieldCount uint16

	// Number of scope fields in this Options Template Record. The Scope
	// Fields are normal Fields, except that they are interpreted as
	// scope at the Collector. A scope field count of N specifies that
	// the first N Field Specifiers in the Template Record are Scope
	// Fields. The Scope Field Count MUST NOT be zero.
	ScopeFieldCount uint16
}

type IPFIXDataRecord struct {
	Data []byte
}
