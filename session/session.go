// Package session provides sessions for the Netflow version 9 and IPFIX
// decoders that need to track templates bound to a session.
package session

import "sync"

const (
	SCOPE_SYSTEM = 1
	SCOPE_INTERFACE = 2
	SCOPE_LINECARD = 3
	SCOPE_NETFLOWCACHE = 4
	SCOPE_TEMPLATE = 5
)

var ScopeTypes = map[uint16]string{
	SCOPE_SYSTEM       : "System",
	SCOPE_INTERFACE    : "Interface",
	SCOPE_LINECARD     : "Line card",
	SCOPE_NETFLOWCACHE : "Netflow cache",
	SCOPE_TEMPLATE     : "Template",
}

const (
	OPTION_SAMPLER_ID = 48
	OPTION_SAMPLER_MODE = 49
	OPTION_SAMPLER_INTERVAL = 50
)

type TemplateFieldSpecifier interface {
	GetType() uint16
	GetLength() uint16
}

type Template interface {
	ID() uint16
	Size() int
	GetFields() []TemplateFieldSpecifier
}

type Field interface {
	GetType() uint16
	GetLength() uint16
	GetBytes() []byte
}

type TypeID struct {
	EnterpriseNumber uint32
	Type uint16
}

type OptionScope struct {
	Type uint16
	Index uint16
}

type Option struct {
	TemplateID uint16
	Scope OptionScope
	EnterpriseNumber uint32
	Type uint16
	Value interface{}
	Bytes []byte
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
	SetOption(uint32, uint16, *Option)
	GetOption(uint32, uint16, uint16, uint16) *Option
}

type basicSession struct {
	sync.RWMutex
	templates map[uint16]Template
	sizes     map[uint16]int
	options   map[TypeID]map[OptionScope]*Option
}

func New() *basicSession {
	return &basicSession{
		templates: make(map[uint16]Template, 65536),
		sizes:     make(map[uint16]int, 65536),
		options:   make(map[TypeID]map[OptionScope]*Option, 256),
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

func (this *basicSession) SetOption(enterprise_number uint32, field_id uint16, option *Option) {
	type_id := TypeID{enterprise_number, field_id}
	options, found := this.options[type_id]
	if(!found) {
		options = make(map[OptionScope]*Option, 256)
		this.options[type_id] = options
	}
	options[option.Scope] = option
}

func (this *basicSession) GetOption(enterprise_number uint32, field_id uint16, scope_type uint16, scope_index uint16) (*Option) {
	options, found := this.options[TypeID{enterprise_number, field_id}]
	if(!found) {
		return nil
	}
	option, found := options[OptionScope{Type: scope_type, Index: scope_index}]
	if(!found) {
		// Try a system-level scope
		option, found = options[OptionScope{Type: SCOPE_SYSTEM, Index: 0}]
		if(!found) {
			return nil
		}
	}
	return option
}

// Test if basicSession is compliant
var _ Session = (*basicSession)(nil)

