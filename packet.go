// Packet netflow offers (Cisco) NetFlow packet parsing capabilities and also
// offers support for IPFIX (or "NetFlow v10") as specified by IETF. Packets
// are decoded in a deterministic way; the first word for a message is read and
// based on the version word the correct parser will be chosen.
//
// Copyrights
//
// NetFlow versions 1, 5, 7 & 8 are © Cisco Systems.
//
// NetFlow version 9 is © 2004 The Internet Society.
//
// References
//
// NetFlow version 1, 5, 7, 8 are covered in
// http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html
//
// NetFlow version 9 is covered in
// http://www.ietf.org/rfc/rfc3954.txt
//
package netflow

const (
	versionUnknown uint16 = 0
)

// Header is a common header for all NetFlow formats
type Header struct {
	Version uint16
}

type FlowHeader interface {
	SampleInterval() int
}

type FlowRecord interface {
}
