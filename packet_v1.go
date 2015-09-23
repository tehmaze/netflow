package netflow

import (
	"encoding/binary"
	"io"
)

// V1Header is a NetFlow v1 header
type V1Header struct {
	Header
	Count     uint16
	SysUptime uint32
	UnixSecs  uint32
	UnixNsecs uint32
}

func (h V1Header) Read(r io.Reader) (err error) {
	if h.Version == 0 {
		if err = binary.Read(r, binary.BigEndian, &h.Version); err != nil {
			return
		}
	}
	return h.readAfterHeader(r)
}

func (h V1Header) readAfterHeader(r io.Reader) (err error) {
	if err = binary.Read(r, binary.BigEndian, &h.Count); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &h.SysUptime); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &h.UnixSecs); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &h.UnixNsecs); err != nil {
		return
	}
	return
}

// V1FlowRecord is a NetFlow v1 Flow Record
type V1FlowRecord struct {
	// SrcAddr is the Source IP address
	SrcAddr uint32
	// DstAddr is the Destination IP address
	DstAddr uint32
	// NextHop is the IP address of next hop router
	NextHop uint32
	// Input is the SNMP index of input interface
	Input uint16
	// Output is the SNMP index of output interface
	Output uint16
	// Count is the number of packets in the flow
	Count uint32
	// Bytes is the number of bytes in the flow
	Bytes uint32
	// First is the SysUptime at start of flow
	First uint32
	// Last is the SysUptime at end of flow
	Last uint32
	// SrcPort is the TCP/UDP source port number or equivalent
	SrcPort uint16
	// DstPort is the TCP/UDP destination port number or equivalent
	DstPort uint16
	// Pad0 are unused bytes
	Pad0 uint16
	// Protocol number (IP)
	Protocol uint8
	// ToS is the IP type of service
	ToS uint8
	// Flags are cumulative OR TCP flags
	Flags uint8
	// Reserved are 3 unused bytes + 5 reserved bytes (zero bytes)
	Reserved uint64
}

func (f *V1FlowRecord) Read(r io.Reader) (err error) {
	return binary.Read(r, binary.BigEndian, f)
}

func (f *V1FlowRecord) SampleInterval() int { return 1 }
