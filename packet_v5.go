package netflow

import (
	"fmt"
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

func (h *V5Header) Unmarshal(r io.Reader) error {
	if h.Version == 0 {
		var err error
		if h.Version, err = readUint16(r); err != nil {
			return err
		}
	}
	return h.unmarshalAfterHeader(r)
}

func (h *V5Header) unmarshalAfterHeader(r io.Reader) error {
	if err := h.V1Header.Unmarshal(r); err != nil {
		return err
	}
	var err error
	if h.FlowSequence, err = readUint32(r); err != nil {
		return err
	}
	if h.EngineType, err = readUint8(r); err != nil {
		return err
	}
	if h.EngineID, err = readUint8(r); err != nil {
		return err
	}
	if h.SamplingInterval, err = readUint16(r); err != nil {
		return err
	}

	return nil
}

type V5FlowRecord struct {
	// SrcAddr is the Source IP address
	SrcAddr LongIPv4
	// DstAddr is the Destination IP address
	DstAddr LongIPv4
	// NextHop is the IP address of next hop router
	NextHop LongIPv4
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

func (f *V5FlowRecord) String() string {
	return fmt.Sprintf("%s/%d:%d -> %s/%d:%d", f.SrcAddr, f.SrcMask, f.SrcPort, f.DstAddr, f.DstMask, f.DstPort)
}

func (f *V5FlowRecord) Unmarshal(r io.Reader) error {
	var err error
	if f.SrcAddr, err = readLongIPv4(r); err != nil {
		return err
	}
	if f.DstAddr, err = readLongIPv4(r); err != nil {
		return err
	}
	if f.NextHop, err = readLongIPv4(r); err != nil {
		return err
	}
	if f.Input, err = readUint16(r); err != nil {
		return err
	}
	if f.Output, err = readUint16(r); err != nil {
		return err
	}
	if f.Count, err = readUint32(r); err != nil {
		return err
	}
	if f.Bytes, err = readUint32(r); err != nil {
		return err
	}
	if f.First, err = readUint32(r); err != nil {
		return err
	}
	if f.Last, err = readUint32(r); err != nil {
		return err
	}
	if f.SrcPort, err = readUint16(r); err != nil {
		return err
	}
	if f.DstPort, err = readUint16(r); err != nil {
		return err
	}
	if f.Pad0, err = readUint16(r); err != nil {
		return err
	}
	if f.Protocol, err = readUint8(r); err != nil {
		return err
	}
	if f.ToS, err = readUint8(r); err != nil {
		return err
	}
	if f.SrcAS, err = readUint16(r); err != nil {
		return err
	}
	if f.DstAS, err = readUint16(r); err != nil {
		return err
	}
	if f.SrcMask, err = readUint8(r); err != nil {
		return err
	}
	if f.DstMask, err = readUint8(r); err != nil {
		return err
	}
	if f.Reserved, err = readUint16(r); err != nil {
		return err
	}
	return nil
}
