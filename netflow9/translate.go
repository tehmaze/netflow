package netflow9

import (
	"fmt"

	"github.com/scalingdata/netflow/session"
	"github.com/scalingdata/netflow/translate"
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
		if i >= len(dr.Fields) {
			break
		}
		f := &dr.Fields[i]
		f.Translated = &TranslatedField{}
		f.Translated.Type = field.Type

		if element, ok := t.Translate.Key(translate.Key{0, field.Type}); ok {
			f.Translated.Name = element.Name
			f.Translated.Value = translate.Bytes(dr.Fields[i].Bytes, element.Type)
		} else if debug {
			debugLog.Printf("no translator element for {0, %d}\n", field.Type)
		}
	}

	return nil
}
