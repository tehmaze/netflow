package netflow

import (
	"fmt"
	"net"
)

func ExampleDecoder() {
	// Boiler plate UDP server
	addr, _ := net.ResolveUDPAddr("udp", ":2055")
	server, _ := net.ListenUDP("udp", addr)

	// This is our decoder
	decoder := NewDecoder()

	// Forever receive messages from the network
	for {
		var msg = make([]byte, 8192)
		if _, _, err := server.ReadFromUDP(msg); err == nil {
			if d, err := decoder.Decode(msg); err != nil {
				// Now feed trough d.Flows()
				fmt.Println(d)
			}
		}
	}
}
