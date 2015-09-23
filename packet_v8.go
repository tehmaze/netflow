package netflow

import (
	"encoding/binary"
	"io"
)

// V8Header is a NetFlow version 8 header
//
// As sepcified at http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006610
type V8Header struct {
	V1Header
	FlowSequence uint32
	EngineType   uint8
	EngineID     uint8
	Aggregation  uint8
	AggVersion   uint8
	Reserved     uint32
}

type V8FlowRecordHeader struct {
	Flows uint32
	Count uint32
	Bytes uint32
	First uint32
	Last  uint32
}

func (h *V8FlowRecordHeader) Read(r io.Reader) (err error) {
	return binary.Read(r, binary.BigEndian, h)
}

type V8RouterASFlowRecord struct {
	V8FlowRecordHeader
	SrcAS             uint16
	DstAS             uint16
	IncomingSNMPIndex uint16
	OutgoingSNMPIndex uint16
}

type V8RouterProtoPortFlowRecord struct {
	V8FlowRecordHeader
	DstPrefix         uint32
	DstMask           uint8
	Pad               uint8
	DstAS             uint32
	OutgoingSNMPIndex uint16
	Reserved          uint16
}

type V8RouterSrcPrefixFlowRecord struct {
	V8FlowRecordHeader
	SrcPrefix         uint32
	SrcMask           uint8
	Pad               uint8
	SrcAS             uint32
	IncomingSNMPIndex uint16
	Reserved          uint16
}

type V8RouterPrefixFlowRecord struct {
	V8FlowRecordHeader
	SrcPrefix         uint32
	DstPrefix         uint32
	SrcMask           uint8
	DstMask           uint8
	Reserved          uint16
	SrcAS             uint16
	DstAS             uint16
	IncomingSNMPIndex uint16
	OutgoingSNMPIndex uint16
}

type V8TosASFlowRecord struct {
	V8FlowRecordHeader
	SrcAS    uint16
	DstAS    uint16
	ToS      uint8
	Pad      uint8
	Reserved uint16
}

type V8TosProtoPortFlowRecord struct {
	V8FlowRecordHeader
	Protocol          uint8
	ToS               uint8
	Reserved          uint16
	SrcPort           uint16
	DstPort           uint16
	IncomingSNMPIndex uint16
	OutgoingSNMPIndex uint16
}

type V8PrePortProtocolFlorRecord struct {
	V8FlowRecordHeader
	SrcPrefix         uint32
	DstPrefix         uint32
	SrcMask           uint8
	DstMask           uint8
	ToS               uint8
	Protocol          uint8
	SrcPort           uint16
	DstPort           uint16
	IncomingSNMPIndex uint16
	OutgoingSNMPIndex uint16
}

type V8TosSrcPrefixFlowRecord struct {
	V8FlowRecordHeader
	SrcPrefix         uint32
	SrcMask           uint8
	ToS               uint8
	SrcAS             uint16
	IncomingSNMPIndex uint16
	Reserved          uint16
}

type V8TosDstPrefixFlowRecord struct {
	V8FlowRecordHeader
	DstPrefix         uint32
	DstMask           uint8
	ToS               uint8
	DstAS             uint16
	OutgoingSNMPIndex uint16
	Reserved          uint16
}

type V8TosPrefixFlowRecord struct {
	V8FlowRecordHeader
	SrcPrefix         uint32
	DstPrefix         uint32
	DstMask           uint8
	SrcMask           uint8
	ToS               uint8
	SrcAS             uint16
	DstAS             uint16
	IncomingSNMPIndex uint16
	OutgoingSNMPIndex uint16
}

type V8DestOnlyFlowRecord struct {
	V8FlowRecordHeader
	OutgoingSNMPIndex uint16
	ToS               uint8
	MarkedToS         uint8
	ExtraCount        uint32
	RouterSC          uint32
}

type V8SrcDstFlowRecord struct {
	V8FlowRecordHeader
	OutgoingSNMPIndex uint16
	IncomingSNMPIndex uint16
	ToS               uint8
	MarkedToS         uint8
	Reserved          uint16
	ExtraCount        uint32
	RouterSC          uint32
}

type V8FullFlowRecord struct {
	V8FlowRecordHeader
	OutgoingSNMPIndex uint16
	IncomingSNMPIndex uint16
	ToS               uint8
	Protocol          uint8
	MarkedToS         uint8
	Pad               uint8
	ExtraCount        uint32
	RouterSC          uint32
}
