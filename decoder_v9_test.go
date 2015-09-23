package netflow

import "net"

func ExampleV9Decoder() {
	// Boiler plate UDP server
	addr, _ := net.ResolveUDPAddr("udp", ":2055")
	server, _ := net.ListenUDP("udp", addr)

	// This is our decoder
	decoder := NewDecoder()

	// Shared cache for all decoders and sources
	cache := make(V9TemplateCache)

	// Forever receive messages from the network
	for {
		var msg = make([]byte, 8192)
		if _, _, err := server.ReadFromUDP(msg); err == nil {
			if d, err := decoder.Decode(msg); err != nil {
				if v9, ok := d.(*V9Decoder); ok {
					v9.Cache = cache
				}

				// Now use d.Next() or feed trough d.Flows()
			}
		}
	}
}
