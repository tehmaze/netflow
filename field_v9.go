package netflow

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

type v9fieldTypeEntry struct {
	Name        string
	Length      int
	String      func([]uint8) string
	Value       func([]uint8) interface{}
	Description string
}

const (
	InBytes = 1 + iota
	InPackets
	Flows
	Protocol
	SrcTOS
	TCPFlags
	L4SrcPort
	IPv4SrcAddr
	SrcMask
	InputSNMP
	L4DstPort
	IPv4DstAddr
	DstMask
	OutputSNMP
	IPv4NextHop
	SrcAS
	DstAS
	BGPIPv4NextHop
	MulDstPackets
	MulDstBytes
	LastSwitched
	FirstSwitched
	OutBytes
	OutPackets
	MinPacketLength
	MaxPacketLength
	IPv6SrcAddr
	IPv6DstAddr
	IPv6SrcMask
	IPv6DstMask
	IPv6FlowLabel
	ICMPType
	MulIGMPType
	SamplingInterval
	SamplingAlgorithm
	FlowActiveTimeout
	FlowInactiveTimeout
	EngineType
	EngineID
	TotalBytesExp
	TotalCountExp
	TotalFlowsExp
	VendorProprietary43
	IPv4SrcPrefix
	IPv4DstPrefix
	MPLSTopLabelType
	MPLSTopLabelAddr
	FlowSamplerID
	FlowSamplerMode
	FlowSamplerRandomInterval
	VendorProprietary50
	MinTTL
	MaxTTL
	IPv4Ident
	DstToS
	IncomingSrcMac
	OutgoingDstMac
	SrcVLAN
	DstVLAN
	IPProtocolVersion
	Direction
	IPv6NextHop
	BGPIPv6NextHop
	IPv6OptionHeaders
	VendorProprietary65
	VendorProprietary66
	VendorProprietary67
	VendorProprietary68
	VendorProprietary69
	MPLSLabel1
	MPLSLabel2
	MPLSLabel3
	MPLSLabel4
	MPLSLabel5
	MPLSLabel6
	MPLSLabel7
	MPLSLabel8
	MPLSLabel9
	MPLSLabel10
	IncomingDstMac
	OutgoingSrcMac
	IfName
	IfDesc
	SamplerName
	InPermanentBytes
	InPermanentCount
	VendorProprietary87
	FragmentOffset
	ForwardingStatus
	MPLSPALRD
	MPLSPrefixLength
	SrcTrafficIndex
	DstTrafficIndex
	ApplicationDescription
	ApplicationTag
	ApplicationName
)

// Every field type ID above 127 is not part of the RFC 3954 specification. These
// fields are in the IPFIX draft, but are also found in NetFlows in the wild.
//
// See https://tools.ietf.org/html/draft-ietf-behave-ipfix-nat-logging-04
const (
	PostNATIPv4SrcAddr         = 225
	PostNATIPv4DstAddr         = 226
	PostNATSrcTransportPort    = 227
	PostNATDstTransportPort    = 228
	NATOriginatingAddressRealm = 229
	NATEvent                   = 230
	IngressVRFID               = 234
	EgressVRFID                = 235
	PostNATIPv6SrcAddr         = 281
	PostNATIPv6DstAddr         = 282
	TimeStamp                  = 323
	PortRangeStart             = 361
	PortRangeEnd               = 362
	PortRangeStepSize          = 363
	PortRangeNumPorts          = 364
)

var v9fieldType = map[uint16]v9fieldTypeEntry{
	InBytes:                    v9fieldTypeEntry{"IN_BYTES", -1, v9fieldToStringUInteger, v9fieldToUint32, "Incoming counter with length N x 8 bits for the number of bytes associated with an IP Flow. By default N is 4"},
	InPackets:                  v9fieldTypeEntry{"IN_PKTS", -1, v9fieldToStringUInteger, v9fieldToUint32, "Incoming counter with length N x 8 bits for the number of packes associated with an IP Flow. By default N is 4"},
	Flows:                      v9fieldTypeEntry{"FLOWS", -1, v9fieldToStringUInteger, v9fieldToUint32, "Number of Flows that were aggregated; by default N is 4"},
	Protocol:                   v9fieldTypeEntry{"PROTOCOL", 1, v9fieldToStringHex, v9fieldToUint8, "IP protocol byte"},
	SrcTOS:                     v9fieldTypeEntry{"SRC_TOS", 1, v9fieldToStringHex, v9fieldToUint8, "Type of service byte setting when entering the incoming interface"},
	TCPFlags:                   v9fieldTypeEntry{"TCP_FLAGS", 1, v9fieldToStringTCPFlags, v9fieldToUint8, "TCP flags; cumulative of all the TCP flags seen in this Flow"},
	L4SrcPort:                  v9fieldTypeEntry{"L4_SRC_PORT", 2, v9fieldToStringUInteger, v9fieldToUint32, "TCP/UDP source port number (for example, FTP, Telnet, or equivalent)"},
	IPv4SrcAddr:                v9fieldTypeEntry{"IPV4_SRC_ADDR", 4, v9fieldToStringIP, v9fieldToIP, "IPv4 source address"},
	SrcMask:                    v9fieldTypeEntry{"SRC_MASK", 1, v9fieldToStringUInteger, v9fieldToUint32, "The number of contiguous bits in the source subnet mask (i.e., the mask in slash notation)"},
	InputSNMP:                  v9fieldTypeEntry{"INPUT_SNMP", -1, v9fieldToStringUInteger, v9fieldToUint32, "Input interface index. By default N is 2, but higher values can be used"},
	L4DstPort:                  v9fieldTypeEntry{"L4_DST_PORT", 2, v9fieldToStringUInteger, v9fieldToUint32, "TCP/UDP destination port number (for example, FTP, Telnet, or equivalent)"},
	IPv4DstAddr:                v9fieldTypeEntry{"IPV4_DST_ADDR", 4, v9fieldToStringIP, v9fieldToIP, "IPv4 destination address"},
	DstMask:                    v9fieldTypeEntry{"DST_MASK", 1, v9fieldToStringUInteger, v9fieldToUint32, "The number of contiguous bits in the destination subnet mask (i.e., the mask in slash notation)"},
	OutputSNMP:                 v9fieldTypeEntry{"OUTPUT_SNMP", -1, v9fieldToStringUInteger, v9fieldToUint32, "Output interface index. By default N is 2, but higher values can be used"},
	IPv4NextHop:                v9fieldTypeEntry{"IPV4_NEXT_HOP", 4, v9fieldToStringIP, v9fieldToIP, "IPv4 address of the next-hop router"},
	SrcAS:                      v9fieldTypeEntry{"SRC_AS", -1, v9fieldToStringUInteger, v9fieldToUint32, "Source BGP autonomous system number where N could be 2 or 4. By default N is 2"},
	DstAS:                      v9fieldTypeEntry{"DST_AS", -1, v9fieldToStringUInteger, v9fieldToUint32, "Destination BGP autonomous system number where N could be 2 or 4. By default N is 2"},
	BGPIPv4NextHop:             v9fieldTypeEntry{"BGP_IPV4_NEXT_HOP", 4, v9fieldToStringIP, v9fieldToIP, "Next-hop router's IP address in the BGP domain"},
	MulDstPackets:              v9fieldTypeEntry{"MUL_DST_PKTS", -1, v9fieldToStringUInteger, v9fieldToUint32, "IP multicast outgoing packet counter with length N x 8 bits for packets associated with the IP Flow. By default N is 4"},
	MulDstBytes:                v9fieldTypeEntry{"MUL_DST_BYTES", -1, v9fieldToStringUInteger, v9fieldToUint32, "IP multicast outgoing Octet (byte) counter with length N x 8 bits for the number of bytes associated with the IP Flow. By default N is 4"},
	LastSwitched:               v9fieldTypeEntry{"LAST_SWITCHED", 4, v9fieldToStringMsecDuration, v9fieldToUint32, "sysUptime in msec at which the last packet of this Flow was switched"},
	FirstSwitched:              v9fieldTypeEntry{"FIRST_SWITCHED", 4, v9fieldToStringMsecDuration, v9fieldToUint32, "sysUptime in msec at which the first packet of this Flow was switched"},
	OutBytes:                   v9fieldTypeEntry{"OUT_BYTES", -1, v9fieldToStringUInteger, v9fieldToUint32, "Outgoing counter with length N x 8 bits for the number of bytes associated with an IP Flow. By default N is 4"},
	OutPackets:                 v9fieldTypeEntry{"OUT_PKTS", -1, v9fieldToStringUInteger, v9fieldToUint32, "Outgoing counter with length N x 8 bits for the number of packets associated with an IP Flow. By default N is 4"},
	MinPacketLength:            v9fieldTypeEntry{"MIN_PKT_LNGTH", 2, v9fieldToStringUInteger, v9fieldToUint32, "Minimum IP packet length on incoming packets of the flow"},
	MaxPacketLength:            v9fieldTypeEntry{"MAX_PKT_LNGTH", 2, v9fieldToStringUInteger, v9fieldToUint32, "Maximum IP packet length on incoming packets of the flow"},
	IPv6SrcAddr:                v9fieldTypeEntry{"IPV6_SRC_ADDR", 16, v9fieldToStringIP, v9fieldToIP, "IPv6 source address"},
	IPv6DstAddr:                v9fieldTypeEntry{"IPV6_DST_ADDR", 16, v9fieldToStringIP, v9fieldToIP, "IPv6 destination address"},
	IPv6SrcMask:                v9fieldTypeEntry{"IPV6_SRC_MASK", 1, v9fieldToStringUInteger, v9fieldToUint32, "Length of the IPv6 source mask in contiguous bits"},
	IPv6DstMask:                v9fieldTypeEntry{"IPV6_DST_MASK", 1, v9fieldToStringUInteger, v9fieldToUint32, "Length of the IPv6 destination mask in contiguous bits"},
	IPv6FlowLabel:              v9fieldTypeEntry{"IPV6_FLOW_LABEL", 3, v9fieldToStringHex, v9fieldAsIs, "IPv6 flow label as per RFC 2460 definition"},
	ICMPType:                   v9fieldTypeEntry{"ICMP_TYPE", 2, v9fieldToStringICMPTypeCode, v9fieldToUint16, "Internet Control Message Protocol (ICMP) packet type; reported as ICMP Type * 256 + ICMP code"},
	MulIGMPType:                v9fieldTypeEntry{"MUL_IGMP_TYPE", 1, v9fieldToStringUInteger, v9fieldToUint32, "Internet Group Management Protocol (IGMP) packet type"},
	SamplingInterval:           v9fieldTypeEntry{"SAMPLING_INTERVAL", 4, v9fieldToStringSamplingInterval, v9fieldToUint32, "When using sampled NetFlow, the rate at which packets are sampled; for example, a value of 100 indicates that one of every hundred packets is sampled"},
	SamplingAlgorithm:          v9fieldTypeEntry{"SAMPLING_ALGORITHM", 1, v9fieldToStringSamplingAlgo, v9fieldToUint8, "For sampled NetFlow platform-wide: 0x01 deterministic sampling, 0x02 random sampling. Use in connection with SAMPLING_INTERVAL"},
	FlowActiveTimeout:          v9fieldTypeEntry{"FLOW_ACTIVE_TIMEOUT", 2, v9fieldToStringUInteger, v9fieldToUint32, "Timeout value (in seconds) for active flow entries in the NetFlow cache"},
	FlowInactiveTimeout:        v9fieldTypeEntry{"FLOW_INACTIVE_TIMEOUT", 2, v9fieldToStringUInteger, v9fieldToUint32, "Timeout value (in seconds) for inactive Flow entries in the NetFlow cache"},
	EngineType:                 v9fieldTypeEntry{"ENGINE_TYPE", 1, v9fieldToStringEngineType, v9fieldToUint8, "Type of Flow switching engine (route processor, linecard, etc...)"},
	EngineID:                   v9fieldTypeEntry{"ENGINE_ID", 1, v9fieldToStringUInteger, v9fieldToUint32, "ID number of the Flow switching engine"},
	TotalBytesExp:              v9fieldTypeEntry{"TOTAL_BYTES_EXP", -1, v9fieldToStringUInteger, v9fieldToUint32, "Counter with length N x 8 bits for the number of bytes exported by the Observation Domain. By default N is 4"},
	TotalCountExp:              v9fieldTypeEntry{"TOTAL_PKTS_EXP", -1, v9fieldToStringUInteger, v9fieldToUint32, "Counter with length N x 8 bits for the number of packets exported by the Observation Domain. By default N is 4"},
	TotalFlowsExp:              v9fieldTypeEntry{"TOTAL_FLOWS_EXP", -1, v9fieldToStringUInteger, v9fieldToUint32, "Counter with length N x 8 bits for the number of Flows exported by the Observation Domain. By default N is 4"},
	VendorProprietary43:        v9fieldTypeEntry{"VENDOR_PROPRIETARY_43", -1, v9fieldToStringHex, v9fieldAsIs, "*Vendor Proprietary*"},
	IPv4SrcPrefix:              v9fieldTypeEntry{"IPV4_SRC_PREFIX", 4, v9fieldToStringIP, v9fieldToIP, "IPv4 source address prefix (specific for Catalyst architecture)"},
	IPv4DstPrefix:              v9fieldTypeEntry{"IPV4_DST_PREFIX", 4, v9fieldToStringIP, v9fieldToIP, "IPv4 destination address prefix (specific for Catalyst architecture)"},
	MPLSTopLabelType:           v9fieldTypeEntry{"MPLS_TOP_LABEL_TYPE", 1, v9fieldToStringMPLSTopLabelType, v9fieldToUint8, "MPLS Top Label Type: 0x00 UNKNOWN, 0x01 TE-MIDPT, 0x02 ATOM, 0x03 VPN, 0x04 BGP, 0x05 LDP"},
	MPLSTopLabelAddr:           v9fieldTypeEntry{"MPLS_TOP_LABEL_IP_ADDR", 4, v9fieldToStringIP, v9fieldToIP, "Forwarding Equivalent Class corresponding to the MPLS Top Label"},
	FlowSamplerID:              v9fieldTypeEntry{"FLOW_SAMPLER_ID", -1, v9fieldToStringUInteger, v9fieldToUint32, "Identifier shown in \"show flow-sampler\". By default N is 4"},
	FlowSamplerMode:            v9fieldTypeEntry{"FLOW_SAMPLER_MODE", 1, v9fieldToStringSamplingAlgo, v9fieldToUint8, "The type of algorithm used for sampling data: 0x02 random sampling. Use in connection with FLOW_SAMPLER_MODE"},
	FlowSamplerRandomInterval:  v9fieldTypeEntry{"FLOW_SAMPLER_RANDOM_INTERVAL", 4, v9fieldToStringUInteger, v9fieldToUint32, "Packet interval at which to sample. Use in connection with FLOW_SAMPLER_MODE"},
	VendorProprietary50:        v9fieldTypeEntry{"VENDOR_PROPRIETARY_50", -1, v9fieldToStringHex, v9fieldAsIs, "*Vendor Proprietary*"},
	MinTTL:                     v9fieldTypeEntry{"MIN_TTL", 1, v9fieldToStringUInteger, v9fieldToUint32, "Minimum TTL on incoming packets of the flow"},
	MaxTTL:                     v9fieldTypeEntry{"MAX_TTL", 1, v9fieldToStringUInteger, v9fieldToUint32, "Maximum TTL on incoming packets of the flow"},
	IPv4Ident:                  v9fieldTypeEntry{"IPV4_IDENT", 2, v9fieldToStringHex, v9fieldToUint16, "The IP v4 identification field"},
	DstToS:                     v9fieldTypeEntry{"DST_TOS", 1, v9fieldToStringHex, v9fieldToUint8, "Type of Service byte setting when exiting outgoing interface"},
	IncomingSrcMac:             v9fieldTypeEntry{"INCOMING_SRC_MAC", 6, v9fieldToStringMAC, v9fieldToHardwareAddr, "Source MAC Address"},
	OutgoingDstMac:             v9fieldTypeEntry{"OUTGOING_DST_MAC", 6, v9fieldToStringMAC, v9fieldToHardwareAddr, "Destination MAC Address"},
	SrcVLAN:                    v9fieldTypeEntry{"SRC_VLAN", 2, v9fieldToStringUInteger, v9fieldToUint32, "Virtual LAN identifier associated with ingress interface"},
	DstVLAN:                    v9fieldTypeEntry{"DST_VLAN", 2, v9fieldToStringUInteger, v9fieldToUint32, "Virtual LAN identifier associated with egress interface"},
	IPProtocolVersion:          v9fieldTypeEntry{"IP_PROTOCOL_VERSION", 1, v9fieldToStringUInteger, v9fieldToUint32, "Internet Protocol Version. Set to 4 for IPv4, set to 6 for IPv6. If not present in the template, then version 4 is assumed"},
	Direction:                  v9fieldTypeEntry{"DIRECTION", 1, v9fieldToStringDirection, v9fieldToUint8, "Flow direction: 0 - ingress flow, 1 - egress flow"},
	IPv6NextHop:                v9fieldTypeEntry{"IPV6_NEXT_HOP", 16, v9fieldToStringIP, v9fieldToIP, "IPv6 address of the next-hop router"},
	BGPIPv6NextHop:             v9fieldTypeEntry{"BGP_IPV6_NEXT_HOP", 16, v9fieldToStringIP, v9fieldToIP, "Next-hop router in the BGP domain"},
	IPv6OptionHeaders:          v9fieldTypeEntry{"IPV6_OPTIONS_HEADERS", 4, v9fieldToStringHex, v9fieldToUint32, "Bit-encoded field identifying IPv6 option headers found in the flow"},
	VendorProprietary65:        v9fieldTypeEntry{"VENDOR_PROPRIETARY_65", -1, v9fieldToStringHex, v9fieldAsIs, "*Vendor Proprietary*"},
	VendorProprietary66:        v9fieldTypeEntry{"VENDOR_PROPRIETARY_66", -1, v9fieldToStringHex, v9fieldAsIs, "*Vendor Proprietary*"},
	VendorProprietary67:        v9fieldTypeEntry{"VENDOR_PROPRIETARY_67", -1, v9fieldToStringHex, v9fieldAsIs, "*Vendor Proprietary*"},
	VendorProprietary68:        v9fieldTypeEntry{"VENDOR_PROPRIETARY_68", -1, v9fieldToStringHex, v9fieldAsIs, "*Vendor Proprietary*"},
	VendorProprietary69:        v9fieldTypeEntry{"VENDOR_PROPRIETARY_69", -1, v9fieldToStringHex, v9fieldAsIs, "*Vendor Proprietary*"},
	MPLSLabel1:                 v9fieldTypeEntry{"MPLS_LABEL_1", 3, v9fieldToStringMPLSLabel, v9fieldToUint8, "MPLS label at position 1 in the stack"},
	MPLSLabel2:                 v9fieldTypeEntry{"MPLS_LABEL_2", 3, v9fieldToStringMPLSLabel, v9fieldToUint8, "MPLS label at position 2 in the stack"},
	MPLSLabel3:                 v9fieldTypeEntry{"MPLS_LABEL_3", 3, v9fieldToStringMPLSLabel, v9fieldToUint8, "MPLS label at position 3 in the stack"},
	MPLSLabel4:                 v9fieldTypeEntry{"MPLS_LABEL_4", 3, v9fieldToStringMPLSLabel, v9fieldToUint8, "MPLS label at position 4 in the stack"},
	MPLSLabel5:                 v9fieldTypeEntry{"MPLS_LABEL_5", 3, v9fieldToStringMPLSLabel, v9fieldToUint8, "MPLS label at position 5 in the stack"},
	MPLSLabel6:                 v9fieldTypeEntry{"MPLS_LABEL_6", 3, v9fieldToStringMPLSLabel, v9fieldToUint8, "MPLS label at position 6 in the stack"},
	MPLSLabel7:                 v9fieldTypeEntry{"MPLS_LABEL_7", 3, v9fieldToStringMPLSLabel, v9fieldToUint8, "MPLS label at position 7 in the stack"},
	MPLSLabel8:                 v9fieldTypeEntry{"MPLS_LABEL_8", 3, v9fieldToStringMPLSLabel, v9fieldToUint8, "MPLS label at position 8 in the stack"},
	MPLSLabel9:                 v9fieldTypeEntry{"MPLS_LABEL_9", 3, v9fieldToStringMPLSLabel, v9fieldToUint8, "MPLS label at position 9 in the stack"},
	MPLSLabel10:                v9fieldTypeEntry{"MPLS_LABEL_10", 3, v9fieldToStringMPLSLabel, v9fieldToUint8, "MPLS label at position 10 in the stack"},
	IncomingDstMac:             v9fieldTypeEntry{"INCOMING_DST_MAC", 6, v9fieldToStringMAC, v9fieldToHardwareAddr, "Incoming destination MAC address"},
	OutgoingSrcMac:             v9fieldTypeEntry{"OUTGOING_SRC_MAC", 6, v9fieldToStringMAC, v9fieldToHardwareAddr, "Outgoing source MAC address"},
	IfName:                     v9fieldTypeEntry{"IF_NAME", -1, v9fieldToStringASCII, v9fieldToString, "Shortened interface name i.e.: \"FE1/0\""},
	IfDesc:                     v9fieldTypeEntry{"IF_DESC", -1, v9fieldToStringASCII, v9fieldToString, "Full interface name i.e.: \"FastEthernet 1/0\""},
	SamplerName:                v9fieldTypeEntry{"SAMPLER_NAME", -1, v9fieldToStringASCII, v9fieldToString, "Name of the flow sampler"},
	InPermanentBytes:           v9fieldTypeEntry{"IN_PERMANENT_BYTES", -1, v9fieldToStringUInteger, v9fieldToUint32, "Running byte counter for a permanent flow. By default N is 4"},
	InPermanentCount:           v9fieldTypeEntry{"IN_PERMANENT_PKTS", -1, v9fieldToStringUInteger, v9fieldToUint32, "Running packet counter for a permanent flow. By default N is 4"},
	VendorProprietary87:        v9fieldTypeEntry{"VENDOR_PROPRIETARY_87", -1, v9fieldToStringHex, v9fieldAsIs, "*Vendor Proprietary*"},
	FragmentOffset:             v9fieldTypeEntry{"FRAGMENT_OFFSET", 2, v9fieldToStringUInteger, v9fieldToUint32, "The fragment-offset value from fragmented IP packets"},
	ForwardingStatus:           v9fieldTypeEntry{"FORWARDING_STATUS", 1, v9fieldToStringHex, v9fieldAsIs, "Forwarding status is encoded on 1 byte with the 2 left bits giving the status and the 6 remaining bits giving the reason code"},
	MPLSPALRD:                  v9fieldTypeEntry{"MPLS_PAL_RD", 8, v9fieldToStringHex, v9fieldAsIs, "MPLS PAL Route Distinguisher"},
	MPLSPrefixLength:           v9fieldTypeEntry{"MPLS_PREFIX_LEN", 1, v9fieldToStringUInteger, v9fieldToUint32, "Number of consecutive bits in the MPLS prefix length"},
	SrcTrafficIndex:            v9fieldTypeEntry{"SRC_TRAFFIC_INDEX", 4, v9fieldToStringUInteger, v9fieldToUint32, "BGP Policy Accounting Source Traffic Index"},
	DstTrafficIndex:            v9fieldTypeEntry{"DST_TRAFFIC_INDEX", 4, v9fieldToStringUInteger, v9fieldToUint32, "BGP Policy Accounting Destination Traffic Index"},
	ApplicationDescription:     v9fieldTypeEntry{"APPLICATION_DESCRIPTION", -1, v9fieldToStringASCII, v9fieldAsIs, "Application description"},
	ApplicationTag:             v9fieldTypeEntry{"APPLICATION_TAG", -1, v9fieldToStringHex, v9fieldAsIs, "8 bits of engine ID, followed by n bits of classification"},
	ApplicationName:            v9fieldTypeEntry{"APPLICATION_NAME", -1, v9fieldToStringASCII, v9fieldAsIs, "Name associated with a classification"},
	PostNATIPv4SrcAddr:         v9fieldTypeEntry{"POST_NAT_IPV4_SRC_ADDR", 4, v9fieldToStringIP, v9fieldToIP, "Post NAT (outside) source IPv4 address"},
	PostNATIPv4DstAddr:         v9fieldTypeEntry{"POST_NAT_IPV4_DST_ADDR", 4, v9fieldToStringIP, v9fieldToIP, "Destination IPv4 address (post translation)"},
	PostNATSrcTransportPort:    v9fieldTypeEntry{"POST_NAT_SRC_TRANSPORT_PORT", 2, v9fieldToStringUInteger, v9fieldToUint16, "Post NAT (translated) source port"},
	PostNATDstTransportPort:    v9fieldTypeEntry{"POST_NAT_DST_TRANSPORT_PORT", 2, v9fieldToStringUInteger, v9fieldToUint16, "Post NAT (translated) destination port"},
	NATOriginatingAddressRealm: v9fieldTypeEntry{"NAT_ORIGINATING_ADDRESS_REALM", 1, v9fieldToStringUInteger, v9fieldToUint8, "Address Realm"},
	NATEvent:                   v9fieldTypeEntry{"NAT_EVENT", 1, v9fieldToStringUInteger, v9fieldToUint8, "Type of event"},
	IngressVRFID:               v9fieldTypeEntry{"INGRESS_VRFID", 2, v9fieldToStringUInteger, v9fieldToUint32, "ID of the ingress VRF"},
	EgressVRFID:                v9fieldTypeEntry{"EGRESS_VRFID", 2, v9fieldToStringUInteger, v9fieldToUint32, "ID of the egress VRF"},
	PostNATIPv6SrcAddr:         v9fieldTypeEntry{"POST_NAT_IPV6_SRC_ADDR", 16, v9fieldToStringIP, v9fieldToIP, "Post NAT (outside) source IPv6 address"},
	PostNATIPv6DstAddr:         v9fieldTypeEntry{"POST_NAT_IPV6_DST_ADDR", 16, v9fieldToStringIP, v9fieldToIP, "Destination IPv6 address (post translation)"},
	TimeStamp:                  v9fieldTypeEntry{"TIME_STAMP", 4, v9fieldToStringUInteger, v9fieldToTime, "Time stamp"},
	PortRangeStart:             v9fieldTypeEntry{"PORT_RANGE_START", 2, v9fieldToStringUInteger, v9fieldToUint16, "Allocated port block start"},
	PortRangeEnd:               v9fieldTypeEntry{"PORT_RANGE_END", 2, v9fieldToStringUInteger, v9fieldToUint16, "Allocated port block end"},
	PortRangeStepSize:          v9fieldTypeEntry{"PORT_RANGE_STEP_SIZE", 2, v9fieldToStringUInteger, v9fieldToUint16, "Step size of next port"},
	PortRangeNumPorts:          v9fieldTypeEntry{"PORT_RANGE_NUM_PORTS", 2, v9fieldToStringUInteger, v9fieldToUint16, "Number of ports"},
}

func v9fieldAsIs(data []byte) interface{} {
	return data
}

func v9fieldToIP(data []byte) interface{} {
	return net.IP(data)
}

func v9fieldToHardwareAddr(data []byte) interface{} {
	return net.HardwareAddr(data)
}

func v9fieldToInt64(data []byte) interface{} {
	var num int64
	for i := 0; i < len(data) && i < 8; i++ {
		num = (num << 8) | int64(data[i])
	}
	return num
}

func v9fieldToString(data []byte) interface{} {
	return string(data)
}

func v9fieldToTime(data []byte) interface{} {
	var num int64
	for i := 0; i < len(data) && i < 8; i++ {
		num = (num << 8) | int64(data[i])
	}
	return time.Unix(num/1000, num%1000)
}

func v9fieldToUint8(data []byte) interface{} {
	if len(data) >= 1 {
		return data[0]
	}
	return uint8(0)
}

func v9fieldToUint16(data []byte) interface{} {
	var num uint16
	for i := 0; i < len(data) && i < 2; i++ {
		num = (num << 8) | uint16(data[i])
	}
	return num
}

func v9fieldToUint32(data []byte) interface{} {
	var num uint32
	for i := 0; i < len(data) && i < 4; i++ {
		num = (num << 8) | uint32(data[i])
	}
	return num
}

func v9fieldToUint64(data []byte) interface{} {
	var num uint64
	for i := 0; i < len(data) && i < 8; i++ {
		num = (num << 8) | uint64(data[i])
	}
	return num
}

func v9fieldToStringUInteger(data []byte) string {
	if len(data) > 8 {
		return "int64 overflow"
	}
	return fmt.Sprintf("%d", binary.BigEndian.Uint64(data))
}

func v9fieldToStringHex(data []byte) string {
	return "0x" + hex.EncodeToString(data)
}

func v9fieldToStringASCII(data []byte) string {
	return string(data)
}

func v9fieldToStringIP(data []byte) string {
	return net.IP(data).String()
}

func v9fieldToStringMAC(data []byte) string {
	return net.HardwareAddr(data).String()
}

func v9fieldToStringTCPFlags(data []byte) (flags string) {
	if data[0]&0x80 > 0 {
		flags += "C"
	} else {
		flags += " "
	}
	if data[0]&0x40 > 0 {
		flags += "E"
	} else {
		flags += " "
	}
	if data[0]&0x20 > 0 {
		flags += "U"
	} else {
		flags += " "
	}
	if data[0]&0x10 > 0 {
		flags += "A"
	} else {
		flags += " "
	}
	if data[0]&0x08 > 0 {
		flags += "P"
	} else {
		flags += " "
	}
	if data[0]&0x04 > 0 {
		flags += "R"
	} else {
		flags += " "
	}
	if data[0]&0x02 > 0 {
		flags += "S"
	} else {
		flags += " "
	}
	if data[0]&0x01 > 0 {
		flags += "F"
	} else {
		flags += " "
	}
	return
}

func v9fieldToStringICMPTypeCode(data []byte) string {
	return fmt.Sprintf("%d/%d", data[0], data[1])
}

func v9fieldToStringMsecDuration(data []byte) string {
	duration := time.Duration(binary.BigEndian.Uint64(data)) * time.Millisecond
	return duration.String()
}

func v9fieldToStringSamplingInterval(data []byte) string {
	return "1 out of " + v9fieldToStringUInteger(data)
}

func v9fieldToStringSamplingAlgo(data []byte) string {
	switch data[0] {
	case 0x01:
		return "Deterministic"
	case 0x02:
		return "Random"
	default:
		return "Unknown"
	}
}

func v9fieldToStringEngineType(data []byte) string {
	switch data[0] {
	case 0x00:
		return "Routing Processor"
	case 0x01:
		return "Linecart"
	default:
		return "Unknown"
	}
}

func v9fieldToStringMPLSTopLabelType(data []byte) string {
	switch data[0] {
	case 0x01:
		return "TE-MIDPT"
	case 0x02:
		return "ATOM"
	case 0x03:
		return "VPN"
	case 0x04:
		return "BGP"
	case 0x05:
		return "LDP"
	default:
		return "UNKNOWN"
	}
}

func v9fieldToStringDirection(data []byte) string {
	switch data[0] {
	case 0:
		return "Ingress"
	case 1:
		return "Egress"
	default:
		return "Unknown"
	}
}

func v9fieldToStringMPLSLabel(bytes []uint8) string {
	var label int
	var exp int
	var bottom int

	label = (int(bytes[0]) << 12) | (int(bytes[1]) << 4) | ((int(bytes[2]) & 0xf0) >> 4)
	exp = int(bytes[2]) & 0x0e
	bottom = int(bytes[0]) & 0x01

	return fmt.Sprintf("%d/%d/%d", label, exp, bottom)
}
