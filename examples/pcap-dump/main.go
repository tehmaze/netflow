package main

import (
	"flag"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/tehmaze/go-netflow"
	"github.com/tehmaze/go-netflow/examples/dump"
)

func main() {
	flag.Parse()

	var (
		decoder = netflow.NewDecoder()
		err     error
	)

	for _, arg := range flag.Args() {
		log.Println("reading", arg)

		var r *pcap.Handle
		if r, err = pcap.OpenOffline(arg); err != nil {
			log.Printf("error reading %s: %v\n", arg, err)
			continue
		}

		packetSource := gopacket.NewPacketSource(r, r.LinkType())

	readingPackets:
		for packet := range packetSource.Packets() {
			log.Println("packet:", packet)

			d, err := decoder.Decode(packet.TransportLayer().LayerPayload())
			if err != nil {
				log.Println("decoder error:", err)
				continue
			}

			for i := 0; i < d.Len(); i++ {
				r, err := d.Next()
				if err != nil {
					log.Println("decoder error:", err)
					continue readingPackets
				}

				dump.Dump(r)
			}
		}
	}
}
