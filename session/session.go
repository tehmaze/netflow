// Package session provides sessions for the Netflow version 9 and IPFIX
// decoders that need to track templates bound to a session.
package session

import "sync"

type Template interface {
	ID() uint16
}

type Session interface {
	Lock()
	Unlock()
	RLock()
	RUnlock()

	// To keep track of maximum record sizes per template
	GetRecordSize(uint16) (size int, found bool)
	SetRecordSize(uint16, int)

	// To keep track of templates
	AddTemplate(Template)
	GetTemplate(uint16) (t Template, found bool)
}

type basicSession struct {
	sync.RWMutex
	templates map[uint16]Template
	sizes     map[uint16]int
}

func New() *basicSession {
	return &basicSession{
		templates: make(map[uint16]Template, 65536),
		sizes:     make(map[uint16]int, 65536),
	}
}

func (s *basicSession) GetRecordSize(tid uint16) (size int, found bool) {
	size, found = s.sizes[tid]
	return
}

func (s *basicSession) SetRecordSize(tid uint16, size int) {
	if s.sizes[tid] < size {
		s.sizes[tid] = size
	}
}

func (s *basicSession) AddTemplate(t Template) {
	s.templates[t.ID()] = t
}

func (s *basicSession) GetTemplate(id uint16) (t Template, found bool) {
	t, found = s.templates[id]
	return
}

// Test if basicSession is compliant
var _ Session = (*basicSession)(nil)
