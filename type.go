package netflow

import "net"

type LongIPv4 uint32

func (l LongIPv4) String() string {
	return net.IP{
		uint8(l >> 24),
		uint8(l >> 16),
		uint8(l >> 8),
		uint8(l),
	}.String()
}
