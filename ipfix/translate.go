package ipfix

import (
	"github.com/tehmaze/netflow/session"
	"github.com/tehmaze/netflow/translate"
)

type TranslatedField struct {
	Name                 string
	InformationElementID uint16
	EnterpriseNumber     uint32
	Value                interface{}
	Bytes                []byte
}

type Translate struct {
	*translate.Translate
}

func NewTranslate(s session.Session) *Translate {
	return &Translate{translate.NewTranslate(s)}
}

func (t *Translate) Record(dr *DataRecord) error {
	if t.Session == nil {
		return nil
	}
	var (
		tm session.Template
		tr TemplateRecord
		ok bool
	)
	if tm, ok = t.Session.GetTemplate(dr.TemplateID); !ok {
		if debug {
			debugLog.Printf("no template for id=%d, can't translate field\n", dr.TemplateID)
		}
		return nil
	}
	if tr, ok = tm.(TemplateRecord); !ok {
		return nil
	}
	if tr.Fields == nil {
		if debug {
			debugLog.Printf("no fields in template id=%d, can't translate\n", dr.TemplateID)
		}
		return nil
	}

	if debug {
		debugLog.Printf("translating %d/%d fields\n", len(dr.Fields), len(tr.Fields))
	}

	for i, field := range tr.Fields {
		if i > len(dr.Fields) {
			break
		}
		f := &dr.Fields[i]
		f.Translated = &TranslatedField{}
		f.Translated.EnterpriseNumber = field.EnterpriseNumber
		f.Translated.InformationElementID = field.InformationElementID

		if element, ok := t.Translate.Key(translate.Key{field.EnterpriseNumber, field.InformationElementID}); ok {
			f.Translated.Name = element.Name
			f.Translated.Value = translate.Bytes(dr.Fields[i].Bytes, element.Type)
			if debug {
				debugLog.Printf("translated {%d, %d} to %s, %v\n", field.EnterpriseNumber, field.InformationElementID, f.Translated.Name, f.Translated.Value)
			}
		} else if debug {
			debugLog.Printf("no translator element for {%d, %d}\n", field.EnterpriseNumber, field.InformationElementID)
		}
	}

	return nil
}
