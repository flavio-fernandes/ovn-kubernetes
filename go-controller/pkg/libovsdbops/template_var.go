package libovsdbops

import (
	"context"
	"regexp"
	"strings"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/ovsdb"
	libovsdb "github.com/ovn-org/libovsdb/ovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
)

const TemplatePrefix = "^"

// Chassis_Template_Var records store (for efficiency reasons) a 'variables'
// map for each chassis.  For simpler CMS code, store templates in memory
// as a (Name, Value) tuple where Value is a map with potentially different
// values on each chassis.
type Template struct {
	Name string

	// Per chassis template value, indexed by chassisID.
	Value map[string]string
}

type TemplateMap map[string]*Template
type ChassisTemplateVarMap map[string]*nbdb.ChassisTemplateVar

// Len returns the number of chasis on which this Template variable is
// instantiated (has a value).
func (t *Template) Len() int {
	return len(t.Value)
}

// ToReferenceString returns the textual representation of a template
// reference, that is, '^<template-name>'.
func (t *Template) ToReferenceString() string {
	return TemplatePrefix + t.Name
}

// IsTemplateReference returns true if 'name' is a valid template reference.
func IsTemplateReference(name string) bool {
	return strings.HasPrefix(name, TemplatePrefix)
}

// TemplateNameFromReference extracts the template name from a textual
// reference to a template.
func TemplateNameFromReference(template string) string {
	return strings.TrimPrefix(template, TemplatePrefix)
}

// MakeTemplateName creates a valid template name by replacing invalid
// characters in the original 'name' with '_'.  Existing '_' are doubled.
func MakeTemplateName(name string) string {
	invalidChars := regexp.MustCompile(`[/\-$@]`)
	name = strings.Replace(name, "_", "__", -1)
	return invalidChars.ReplaceAllString(name, "_")
}

// MakeTemplate intializes a named Template struct with 0 values.
func MakeTemplate(name string) *Template {
	return &Template{Name: name, Value: map[string]string{}}
}

func forEachNBTemplateInMaps(templateMaps []TemplateMap, callback func(nbTemplate *nbdb.ChassisTemplateVar)) {
	// First flatten the maps into *nbdb.ChassisTemplateVar records:
	flattened := ChassisTemplateVarMap{}
	for _, templateMap := range templateMaps {
		for _, template := range templateMap {
			for chassisName, templateValue := range template.Value {
				if templateValue == "" {
					continue
				}
				nbTemplate, found := flattened[chassisName]
				if !found {
					nbTemplate = &nbdb.ChassisTemplateVar{
						Chassis:   chassisName,
						Variables: map[string]string{},
					}
					flattened[chassisName] = nbTemplate
				}
				nbTemplate.Variables[template.Name] = templateValue
			}
		}
	}

	// Now walk the flattened records:
	for _, nbTemplate := range flattened {
		callback(nbTemplate)
	}
}

// ListTemplates looks up all chassis template variables.  It returns
// libovsdb.Templates values indexed by template name.
func ListTemplates(nbClient libovsdbclient.Client) (templatesByName TemplateMap, err error) {
	templatesByName = TemplateMap{}
	err = nil
	ctx, cancel := context.WithTimeout(context.Background(), types.OVSDBTimeout)
	defer cancel()

	templatesList := []*nbdb.ChassisTemplateVar{}
	err = nbClient.List(ctx, &templatesList)
	if err != nil {
		return
	}

	for _, nbTemplate := range templatesList {
		for name, perChassisValue := range nbTemplate.Variables {
			tv, found := templatesByName[name]
			if !found {
				tv = MakeTemplate(name)
				templatesByName[name] = tv
			}
			tv.Value[nbTemplate.Chassis] = perChassisValue
		}
	}
	return
}

func mutateChassisTemplateVarOps(nbClient libovsdbclient.Client, mutator ovsdb.Mutator,
	ops []libovsdb.Operation, templateVars ...TemplateMap) ([]libovsdb.Operation, error) {
	opModels := []operationModel{}
	forEachNBTemplateInMaps(templateVars, func(nbTemplate *nbdb.ChassisTemplateVar) {
		opModels = append(opModels, operationModel{
			Model: nbTemplate,
			ModelPredicate: func(item *nbdb.ChassisTemplateVar) bool {
				return item.Chassis == nbTemplate.Chassis
			},
			OnModelMutations: []interface{}{&nbTemplate.Variables},
			ErrNotFound:      false,
			BulkOp:           false,
			InsertMutator:    mutator,
		})
	})

	modelClient := newModelClient(nbClient)
	return modelClient.CreateOrUpdateOps(ops, opModels...)
}

func CreateChassisTemplateVarOps(nbClient libovsdbclient.Client,
	ops []libovsdb.Operation, templateVars ...TemplateMap) ([]libovsdb.Operation, error) {

	return mutateChassisTemplateVarOps(nbClient, ovsdb.MutateOperationInsert,
		ops, templateVars...)
}

func CreateOrUpdateChassisTemplateVarOps(nbClient libovsdbclient.Client,
	ops []libovsdb.Operation, templateVars ...TemplateMap) ([]libovsdb.Operation, error) {

	return mutateChassisTemplateVarOps(nbClient, MutateOperationUpdate,
		ops, templateVars...)
}

func DeleteChassisTemplateVarOps(nbClient libovsdbclient.Client,
	ops []libovsdb.Operation, templateVars ...TemplateMap) ([]libovsdb.Operation, error) {
	opModels := []operationModel{}
	forEachNBTemplateInMaps(templateVars, func(nbTemplate *nbdb.ChassisTemplateVar) {
		deleteNbTemplate := &nbdb.ChassisTemplateVar{
			Chassis:   nbTemplate.Chassis,
			Variables: map[string]string{},
		}
		for name := range nbTemplate.Variables {
			deleteNbTemplate.Variables[name] = ""
		}
		opModels = append(opModels, operationModel{
			Model: deleteNbTemplate,
			ModelPredicate: func(item *nbdb.ChassisTemplateVar) bool {
				return item.Chassis == deleteNbTemplate.Chassis
			},
			OnModelMutations: []interface{}{&deleteNbTemplate.Variables},
			ErrNotFound:      false,
			BulkOp:           false,
		})
	})

	modelClient := newModelClient(nbClient)
	return modelClient.DeleteOps(ops, opModels...)
}

func CreateOrUpdateChassisTemplateVar(nbClient libovsdbclient.Client, templateVars ...TemplateMap) error {
	ops, err := CreateOrUpdateChassisTemplateVarOps(nbClient, nil, templateVars...)
	if err != nil {
		return err
	}
	_, err = TransactAndCheck(nbClient, ops)
	return err
}

func DeleteChassisTemplateVarByName(nbClient libovsdbclient.Client, templateVarNames []string) error {
	deleteTemplateVar := &nbdb.ChassisTemplateVar{
		Variables: make(map[string]string, len(templateVarNames)),
	}
	for _, templateName := range templateVarNames {
		deleteTemplateVar.Variables[templateName] = ""
	}
	opModel := operationModel{
		Model: deleteTemplateVar,
		ModelPredicate: func(item *nbdb.ChassisTemplateVar) bool {
			for _, templateName := range templateVarNames {
				if _, found := item.Variables[templateName]; found {
					return true
				}
			}
			return false
		},
		OnModelMutations: []interface{}{&deleteTemplateVar.Variables},
		ErrNotFound:      false,
		BulkOp:           true,
	}

	m := newModelClient(nbClient)
	return m.Delete([]operationModel{opModel}...)
}

// DeleteChassisTemplateRecord deletes all complete Chassis_Template_Var
// records referring to chassis that are part of 'chassisIDs'.  This should
// be used to completely cleanup the NB when chassis disappear from the SB.
func DeleteChassisTemplateRecord(nbClient libovsdbclient.Client, chassisIDs ...string) error {
	opModels := make([]operationModel, 0, len(chassisIDs))
	for _, chassisID := range chassisIDs {
		opModels = append(opModels, operationModel{
			Model: &nbdb.ChassisTemplateVar{},
			ModelPredicate: func(item *nbdb.ChassisTemplateVar) bool {
				return item.Chassis == chassisID
			},
			ErrNotFound: false,
			BulkOp:      true,
		})
	}
	m := newModelClient(nbClient)
	return m.Delete(opModels...)
}
