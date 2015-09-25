package main

import (
	"bytes"
	"flag"
	"log"
	"net"

	"github.com/tehmaze/go-netflow"
	"github.com/tehmaze/go-netflow/common/session"
	"github.com/tehmaze/go-netflow/ipfix"
	"github.com/tehmaze/go-netflow/netflow1"
	"github.com/tehmaze/go-netflow/netflow5"
	"github.com/tehmaze/go-netflow/netflow6"
	"github.com/tehmaze/go-netflow/netflow7"
	"github.com/tehmaze/go-netflow/netflow9"
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

	s := session.New()
	d := netflow.NewDecoder(s)
	for {
		buf := make([]byte, 8192)
		var remote *net.UDPAddr
		if _, remote, err = server.ReadFromUDP(buf); err != nil {
			log.Printf("error reading from %s: %v\n", remote, err)
			continue
		}

		log.Printf("received %d bytes from %s\n", len(buf), remote)

		m, err := d.Read(bytes.NewBuffer(buf))
		if err != nil {
			log.Println("decoder error:", err)
			continue
		}

		switch p := m.(type) {
		case *netflow1.Packet:
			netflow1.Dump(p)

		case *netflow5.Packet:
			netflow5.Dump(p)

		case *netflow6.Packet:
			netflow6.Dump(p)

		case *netflow7.Packet:
			netflow7.Dump(p)

		case *netflow9.Packet:
			netflow9.Dump(p)

		case *ipfix.Message:
			ipfix.Dump(p)
		}
	}
}
