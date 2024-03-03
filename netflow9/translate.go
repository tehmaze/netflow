package netflow9

import (
	"fmt"

	"github.com/tehmaze/netflow/session"
	"github.com/tehmaze/netflow/translate"
)

type TranslatedField struct {
	Name  string
	Type  uint16
	Value interface{}
	Bytes []byte
}

func (tf TranslatedField) String() string {
	return fmt.Sprintf("%s=%v", tf.Name, tf.Value)
}

type Translate struct {
	*translate.Translate
}

func NewTranslate(s session.Session) *Translate {
	return &Translate{translate.NewTranslate(s)}
}

func (t *Translate) Record(dr *DataRecord) error {
	if t.Session == nil {
		if debug {
			debugLog.Println("no session, can't translate field")
		}
		return nil
	}
	var (
		tm session.Template
		ok bool
	)
	if tm, ok = t.Session.GetTemplate(dr.TemplateID); !ok {
		if debug {
			debugLog.Printf("no template for id=%d, can't translate field\n", dr.TemplateID)
		}
		return nil
	}
	fields := tm.GetFields()
	if fields == nil {
		if debug {
			debugLog.Printf("no fields in template id=%d, can't translate\n", dr.TemplateID)
		}
		return nil
	}

	if debug {
		debugLog.Printf("translating %d/%d fields\n", len(dr.Fields), len(fields))
	}

	option_template, is_option := tm.(*OptionTemplateRecord)
	if(is_option) {
		dr.OptionScopes = make([]session.OptionScope, len(option_template.Scopes))
		for i, scope_template := range option_template.Scopes {
			scope := &dr.OptionScopes[i]
			scope.Type = scope_template.Type
			switch(scope.Type) {
				case session.SCOPE_SYSTEM:
					// Do nothing, there's no value for system scope
				case session.SCOPE_INTERFACE:
					scope.Index = translate.Bytes(dr.Fields[i].Bytes, translate.Uint16).(uint16)
				case session.SCOPE_LINECARD:
					// TODO:  Figure out data length/type and do something with this
					continue
				case session.SCOPE_NETFLOWCACHE:
					// TODO:  Figure out data length/type and do something with this
					continue
				case session.SCOPE_TEMPLATE:
					// TODO:  Figure out data length/type and do something with this
					continue
			}
		}
	}

	for i, field := range fields {
		if i >= len(dr.Fields) {
			break
		}
		f := &dr.Fields[i]
		f.Translated = &TranslatedField{}
		f.Translated.Type = field.GetType()

		if element, ok := t.Translate.Key(translate.Key{0, field.GetType()}); ok {
			f.Translated.Name = element.Name
			f.Translated.Value = translate.Bytes(dr.Fields[i].Bytes, element.Type)
		} else if debug {
			debugLog.Printf("no translator element for {0, %d}\n", field.GetType())
		}
	}

	return nil
}

