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

func (t *Translate) Record(dr *DataRecord, tm session.Template) error {
	if t.Session == nil {
		return nil
	}
	tm, ok := t.Session.GetTemplate(dr.TemplateID)
	if !ok {
		if(debug) {
			debugLog.Printf("no template for id=%d, can't translate field\n", dr.TemplateID)
		}
		return nil
	}
	fields := tm.GetFields()
	if fields == nil {
		if(debug) {
			debugLog.Printf("no fields in template id=%d, can't translate\n", dr.TemplateID)
		}
		return nil
	}

	if(debug) {
		debugLog.Printf("translating %d/%d fields\n", len(fields), len(dr.Fields))
	}

	option_template, is_option := tm.(*OptionsTemplateRecord)
	if(is_option) {
		dr.OptionScopes = make(Fields, len(option_template.ScopeFields))
		for i, field := range option_template.ScopeFields {
			t.translate_field(&dr.OptionScopes[i], field)
		}
	}

	for i, field := range fields {
		if i > len(dr.Fields) {
			break
		}

		t.translate_field(&dr.Fields[i], field.(FieldSpecifier))
	}

	return nil
}

func (this *Translate) translate_field(f *Field, fs FieldSpecifier) error {
	f.Translated = &TranslatedField{
		EnterpriseNumber: fs.EnterpriseNumber,
		InformationElementID: fs.InformationElementID,
	}

	element, ok := this.Translate.Key(translate.Key{fs.EnterpriseNumber, fs.InformationElementID})
	if(ok) {
		f.Translated.Name = element.Name
		f.Translated.Value = translate.Bytes(f.Bytes, element.Type)
		if(debug) {
			debugLog.Printf("translated {%d, %d} (%v) to %s, %v\n", fs.EnterpriseNumber, fs.InformationElementID, f.Bytes, f.Translated.Name, f.Translated.Value)
		}
	} else {
		if(debug) {
			debugLog.Printf("no translator element for {%d, %d}\n", fs.EnterpriseNumber, fs.InformationElementID)
		}
	}

	return nil
}

