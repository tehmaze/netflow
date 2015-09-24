/*
Package netflow offers (Cisco) NetFlow packet parsing capabilities and also
offers support for IPFIX (or "NetFlow v10") as specified by IETF. Packets
are decoded in a deterministic way; the first word for a message is read and
based on the version word the correct parser will be chosen.

Copyrights

NetFlow versions 1, 5, 6, 7 and 8 are © Cisco Systems.

NetFlow version 9 is © 2004 The Internet Society.

Internet Protocol Flow Information Export (IPFIX) is an IETF protocol.

References

NetFlow version 1, 5, 7, 8 are covered in
http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html

NetFlow version 9 is covered in the following documents:
 RFC3954 - NetFlow Version 9

Internet Protocol Flow Information Export (IPFIX) is documented in the following documents:
 RFC3955 - Candidate Protocols for IP Flow Information Export (IPFIX)
 RFC5103 - Bidirectional Flow Export Using IP Flow Information Export
 RFC5153 - IPFIX Implementation Guidelines
 RFC5470 - Architecture for IP Flow Information Export
 RFC5471 - Guidelines for IP Flow Information Export (IPFIX) Testing
 RFC5472 - IP Flow Information Export (IPFIX) Applicability
 RFC5473 - Reducing Redundancy in IP Flow Information Export (IPFIX) and Packet Sampling (PSAMP) Reports
 RFC7011 - Specification of the IP Flow Information Export (IPFIX) Protocol for the Exchange of IP Traffic Flow Information (IPFIX)
 RFC7012 - Information Model for IP Flow Information Export
 RFC7013 - Guidelines for Authors and Reviewers of IP Flow Information Export (IPFIX) Information Elements
 RFC7014 - Flow Selection Techniques
 RFC7015 - Flow Aggregation for the IP Flow Information Export (IPFIX) Protocol

Terminology

The terminology in this package reflects the terminology as used in RFC3954:

   +------------------+---------------------------------------------+
   |                  |                    Contents                 |
   |                  +--------------------+------------------------+
   |     FlowSet      | Template  Record   |    Data Record         |
   +------------------+--------------------+------------------------+
   |                  |                    |  Flow Data Record(s)   |
   | Data FlowSet     |          /         |          or            |
   |                  |                    | Options Data Record(s) |
   +------------------+--------------------+------------------------+
   | Template FlowSet | Template Record(s) |           /            |
   +------------------+--------------------+------------------------+
   | Options Template | Options Template   |           /            |
   | FlowSet          | Record(s)          |                        |
   +------------------+--------------------+------------------------+

A Data FlowSet is composed of an Options Data Record(s) or Flow Data
Record(s).  No Template Record is included. A Template Record defines
the Flow Data Record, and an Options Template Record defines the
Options Data Record.

A Template FlowSet is composed of Template Record(s).  No Flow or
Options Data Record is included.

An Options Template FlowSet is composed of Options Template
Record(s).  No Flow or Options Data Record is included.
*/
package netflow
