package netflow

import "io"

const (
	VersionUnknown uint16 = 0 + iota
	Version1
	_ // Version 2 was never released
	_ // Version 3 was never released
	_ // Version 4 was never released
	Version5
	Version6
	Version7
	Version8
	Version9
	VersionIPFIX
)

type VersionHeader interface {
	GetVersion() uint16
	SetVersion(uint16)
	String() string
	Unmarshal(io.Reader) error
}

// Header is a common header for all NetFlow formats
type Header struct {
	Version uint16
}

// ExportRecord is a flow set, template or options template.
type ExportRecord interface {
	Bytes() []byte
	Len() int
	String() string
	//GetVersion() uint16
}

func structLen(s interface{}) int {
	return 0
}

func structPack(s interface{}) []byte {
	return []byte{}
}
