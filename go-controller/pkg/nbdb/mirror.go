// Code generated by "libovsdb.modelgen"
// DO NOT EDIT.

package nbdb

import "github.com/ovn-org/libovsdb/model"

type (
	MirrorFilter = string
	MirrorType   = string
)

var (
	MirrorFilterFromLport MirrorFilter = "from-lport"
	MirrorFilterToLport   MirrorFilter = "to-lport"
	MirrorTypeGre         MirrorType   = "gre"
	MirrorTypeErspan      MirrorType   = "erspan"
)

// Mirror defines an object in Mirror table
type Mirror struct {
	UUID        string            `ovsdb:"_uuid"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Filter      MirrorFilter      `ovsdb:"filter"`
	Index       int               `ovsdb:"index"`
	Name        string            `ovsdb:"name"`
	Sink        string            `ovsdb:"sink"`
	Type        MirrorType        `ovsdb:"type"`
}

func copyMirrorExternalIDs(a map[string]string) map[string]string {
	if a == nil {
		return nil
	}
	b := make(map[string]string, len(a))
	for k, v := range a {
		b[k] = v
	}
	return b
}

func equalMirrorExternalIDs(a, b map[string]string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || v != w {
			return false
		}
	}
	return true
}

func (a *Mirror) DeepCopyInto(b *Mirror) {
	*b = *a
	b.ExternalIDs = copyMirrorExternalIDs(a.ExternalIDs)
}

func (a *Mirror) DeepCopy() *Mirror {
	b := new(Mirror)
	a.DeepCopyInto(b)
	return b
}

func (a *Mirror) CloneModelInto(b model.Model) {
	c := b.(*Mirror)
	a.DeepCopyInto(c)
}

func (a *Mirror) CloneModel() model.Model {
	return a.DeepCopy()
}

func (a *Mirror) Equals(b *Mirror) bool {
	return a.UUID == b.UUID &&
		equalMirrorExternalIDs(a.ExternalIDs, b.ExternalIDs) &&
		a.Filter == b.Filter &&
		a.Index == b.Index &&
		a.Name == b.Name &&
		a.Sink == b.Sink &&
		a.Type == b.Type
}

func (a *Mirror) EqualsModel(b model.Model) bool {
	c := b.(*Mirror)
	return a.Equals(c)
}

var _ model.CloneableModel = &Mirror{}
var _ model.ComparableModel = &Mirror{}
