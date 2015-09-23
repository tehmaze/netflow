package netflow

import (
	"encoding/binary"
	"io"
)

// V5Header is a NetFlow v5 header
//
// As specified at http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006108
type V5Header struct {
	V1Header
	FlowSequence     uint32
	EngineType       uint8
	EngineID         uint8
	SamplingInterval uint16
}

func (h V5Header) Read(r io.Reader) (err error) {
	if h.Version == 0 {
		if err = binary.Read(r, binary.BigEndian, &h.Version); err != nil {
			return
		}
	}
	return h.readAfterHeader(r)
}

func (h V5Header) readAfterHeader(r io.Reader) (err error) {
	if err = h.V1Header.Read(r); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &h.FlowSequence); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &h.EngineType); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &h.EngineID); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &h.SamplingInterval); err != nil {
		return
	}
	return
}

type V5FlowRecord struct {
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
	// TCPFlags are the TCP header flags
	TCPFlags uint8
	// Protocol number (IP)
	Protocol uint8
	// ToS is the IP type of service
	ToS uint8
	// SrcAS is the Autonomous system number of the source, either origin or peer
	SrcAS uint16
	// DstAS is the Autonomous system number of the destination, either origin or peer
	DstAS uint16
	// SrcMask are the source address prefix mask bits
	SrcMask uint8
	// DstMask are the destination address prefix mask bits
	DstMask uint8
	// Reserved are 2 bytes of padding
	Reserved uint16
}

func (f *V5FlowRecord) Read(r io.Reader) (err error) {
	return binary.Read(r, binary.BigEndian, f)
}
