package main

import (
	"flag"
	"log"
	"net"

	"github.com/tehmaze/go-netflow"
	"github.com/tehmaze/go-netflow/examples/dump"
)

func main() {
	listen := flag.String("addr", ":2055", "Listen address")
	flag.Parse()

	var addr *net.UDPAddr
	var err error
	if addr, err = net.ResolveUDPAddr("udp", *listen); err != nil {
		log.Fatal(err)
	}

	var server *net.UDPConn
	if server, err = net.ListenUDP("udp", addr); err != nil {
		log.Fatal(err)
	}

	cache := make(netflow.V9TemplateCache)
	flows := make(chan netflow.FlowRecord)
	decoder := netflow.NewDecoder()

	go dump.Dump(flows)

	for {
		buf := make([]byte, 8192)
		var remote *net.UDPAddr
		if _, remote, err = server.ReadFromUDP(buf); err != nil {
			log.Printf("error reading from %s: %v\n", remote, err)
			continue
		}

		log.Printf("received %d bytes from %s\n", len(buf), remote)

		var vd netflow.VersionDecoder
		if vd, err = decoder.Decode(buf); err != nil {
			log.Println("error finding suitable decoder:", err)
			continue
		}

		log.Printf("remote %s using decoder %T\n", remote, vd)
		switch d := vd.(type) {
		case *netflow.V9Decoder:
			d.Cache = cache
		}

		if err = vd.Flows(flows); err != nil {
			log.Printf("error decoding flows from %s: %v\n", remote, err)
			continue
		}
	}
}
