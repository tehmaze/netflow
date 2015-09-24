package netflow

import (
	"fmt"
	"io"
	"time"
)

// V1Header is a NetFlow v1 header
type V1Header struct {
	Header
	Count     uint16
	SysUptime uint32
	UnixSecs  uint32
	UnixNsecs uint32
}

func (h *V1Header) String() string {
	return fmt.Sprintf("v=%d, count=%d, uptime=%s, time=%s",
		h.Version, h.Count, time.Duration(h.SysUptime)*time.Second, time.Unix(int64(h.UnixSecs), int64(h.UnixNsecs)))
}

func (h *V1Header) Unmarshal(r io.Reader) error {
	if h.Version == 0 {
		var err error
		if h.Version, err = readUint16(r); err != nil {
			return err
		}
	}
	return h.unmarshalAfterHeader(r)
}

func (h *V1Header) unmarshalAfterHeader(r io.Reader) (err error) {
	if h.Count, err = readUint16(r); err != nil {
		return err
	}
	if h.SysUptime, err = readUint32(r); err != nil {
		return err
	}
	if h.UnixSecs, err = readUint32(r); err != nil {
		return err
	}
	if h.UnixNsecs, err = readUint32(r); err != nil {
		return err
	}

	return nil
}

// V1FlowRecord is a NetFlow v1 Flow Record
type V1FlowRecord struct {
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
	// Packets is the number of packets in the flow
	Packets uint32
	// Octets is the number of bytes in the flow
	Octets uint32
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

func (r *V1FlowRecord) Bytes() []byte {
	return structPack(r)
}

func (r *V1FlowRecord) Len() int {
	return structLen(r)
}

func (r *V1FlowRecord) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d", r.SrcAddr, r.SrcPort, r.DstAddr, r.DstPort)
}

func (r *V1FlowRecord) Unmarshal(h io.Reader) (err error) {
	if r.SrcAddr, err = readLongIPv4(h); err != nil {
		return err
	}
	if r.DstAddr, err = readLongIPv4(h); err != nil {
		return err
	}
	if r.NextHop, err = readLongIPv4(h); err != nil {
		return err
	}
	if r.Input, err = readUint16(h); err != nil {
		return err
	}
	if r.Output, err = readUint16(h); err != nil {
		return err
	}
	if r.Packets, err = readUint32(h); err != nil {
		return err
	}
	if r.Octets, err = readUint32(h); err != nil {
		return err
	}
	if r.First, err = readUint32(h); err != nil {
		return err
	}
	if r.Last, err = readUint32(h); err != nil {
		return err
	}
	if r.SrcPort, err = readUint16(h); err != nil {
		return err
	}
	if r.DstPort, err = readUint16(h); err != nil {
		return err
	}
	if r.Pad0, err = readUint16(h); err != nil {
		return err
	}
	if r.Protocol, err = readUint8(h); err != nil {
		return err
	}
	if r.ToS, err = readUint8(h); err != nil {
		return err
	}
	if r.Flags, err = readUint8(h); err != nil {
		return err
	}
	if r.Reserved, err = readUint64(h); err != nil {
		return err
	}
	return nil
}

func (f *V1FlowRecord) SampleInterval() int { return 1 }
