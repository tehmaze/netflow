package dump

import (
	"fmt"
	"log"

	"github.com/tehmaze/go-netflow"
)

var (
	v9Cache = make(map[uint16]*netflow.V9TemplateRecord, 0)
)

// Dump reads and dumps flows
func Dump(r netflow.ExportRecord) {
	log.Printf("received export record %T: %s\n", r, r)
	switch f := r.(type) {
	case *netflow.V1FlowRecord:
		fmt.Printf("%s:%d -> %s:%d\n", f.SrcAddr, f.SrcPort, f.DstAddr, f.DstPort)
		fmt.Printf("  protocol: %d / tos: %d, flags: %d\n", f.Protocol, f.ToS, f.Flags)
		fmt.Printf("  next hop: %s\n", f.NextHop)
		fmt.Printf("  counters: %d packets, %d bytes\n", f.Packets, f.Octets)

	case *netflow.V5FlowRecord:
		fmt.Printf("%s/%d:%d -> %s/%d:%d\n", f.SrcAddr, f.SrcMask, f.SrcPort, f.DstAddr, f.DstMask, f.DstPort)
		fmt.Printf("  protocol: %d / tos: %d, flags: %d\n", f.Protocol, f.ToS, f.TCPFlags)
		fmt.Printf("  next hop: %s\n", f.NextHop)
		fmt.Printf("  counters: %d packets, %d bytes\n", f.Packets, f.Octets)
		fmt.Printf("  asnumber: %d -> %d\n", f.SrcAS, f.DstAS)

	case *netflow.V9TemplateFlowSet:
		for _, record := range f.Records {
			switch record.FieldCount {
			case 0:
				if v9Cache[record.TemplateID] != nil {
					fmt.Printf("  expire template with id %d\n", record.TemplateID)
					delete(v9Cache, record.TemplateID)
				}

			default:
				if v9Cache[record.TemplateID] == nil {
					fmt.Printf("  new template with id %d\n", record.TemplateID)
					v9Cache[record.TemplateID] = record
				}
			}
		}

	case *netflow.V9DataFlowSet:
		if v9Cache[f.ID] == nil {
			fmt.Printf("  no template with id %d\n", f.ID)
			return
		}

		template := v9Cache[f.ID]
		set, err := template.DecodeFlowSet(f)
		if err != nil {
			fmt.Println("  error decoding flow set:", err)
			return
		}
		fmt.Printf("  flow set %T: %d fields\n", set, len(set))
		for _, record := range set {
			fmt.Printf("    record %T:\n", record)
			for k, v := range record.Map(template) {
				fmt.Printf("      %s: %v\n", k, v)
			}
		}
		//fmt.Printf("%s/%d:%d -> %s/%d:%d\n", f.Values)
		//for key, value := range f.Map() {
		//	fmt.Printf("  %s: %v\n", key, value)
		//}
	}
}
