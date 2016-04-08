package netflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/scalingdata/netflow/session"
	"github.com/scalingdata/netflow/ipfix"
	"github.com/scalingdata/netflow/netflow1"
	"github.com/scalingdata/netflow/netflow5"
	"github.com/scalingdata/netflow/netflow6"
	"github.com/scalingdata/netflow/netflow7"
	"github.com/scalingdata/netflow/netflow9"
)

// Decoder for NetFlow messages.
type Decoder struct {
	session.Session
}

// Message generlized interface.
type Message interface {
}

// NewDecoder sets up a decoder suitable for reading NetFlow packets.
func NewDecoder(s session.Session) *Decoder {
	return &Decoder{s}
}

// Read a single Netflow message from the network. If an error is returned,
// there is no guarantee the following reads will be succesful.
func (d *Decoder) Read(r io.Reader) (Message, error) {
	data := [2]byte{}
	if _, err := r.Read(data[:]); err != nil {
		return nil, err
	}

	version := binary.BigEndian.Uint16(data[:])
	buffer := bytes.NewBuffer(data[:])
	mr := io.MultiReader(buffer, r)

	switch version {
	case netflow1.Version:
		return netflow1.Read(mr)

	case netflow5.Version:
		return netflow5.Read(mr)

	case netflow6.Version:
		return netflow6.Read(mr)

	case netflow7.Version:
		return netflow7.Read(mr)

	case netflow9.Version:
		return netflow9.Read(mr, d.Session, nil)

	case ipfix.Version:
		return ipfix.Read(mr, d.Session, nil)

	default:
		return nil, fmt.Errorf("netflow: unsupported version %d", version)
	}
}
