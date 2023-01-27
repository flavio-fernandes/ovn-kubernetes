// Code generated by "libovsdb.modelgen"
// DO NOT EDIT.

package nbdb

import "github.com/ovn-org/libovsdb/model"

// StaticMACBinding defines an object in Static_MAC_Binding table
type StaticMACBinding struct {
	UUID               string `ovsdb:"_uuid"`
	IP                 string `ovsdb:"ip"`
	LogicalPort        string `ovsdb:"logical_port"`
	MAC                string `ovsdb:"mac"`
	OverrideDynamicMAC bool   `ovsdb:"override_dynamic_mac"`
}

func (a *StaticMACBinding) DeepCopyInto(b *StaticMACBinding) {
	*b = *a
}

func (a *StaticMACBinding) DeepCopy() *StaticMACBinding {
	b := new(StaticMACBinding)
	a.DeepCopyInto(b)
	return b
}

func (a *StaticMACBinding) CloneModelInto(b model.Model) {
	c := b.(*StaticMACBinding)
	a.DeepCopyInto(c)
}

func (a *StaticMACBinding) CloneModel() model.Model {
	return a.DeepCopy()
}

func (a *StaticMACBinding) Equals(b *StaticMACBinding) bool {
	return a.UUID == b.UUID &&
		a.IP == b.IP &&
		a.LogicalPort == b.LogicalPort &&
		a.MAC == b.MAC &&
		a.OverrideDynamicMAC == b.OverrideDynamicMAC
}

func (a *StaticMACBinding) EqualsModel(b model.Model) bool {
	c := b.(*StaticMACBinding)
	return a.Equals(c)
}

var _ model.CloneableModel = &StaticMACBinding{}
var _ model.ComparableModel = &StaticMACBinding{}
