package libovsdbops

import (
	"fmt"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/model"
	libovsdb "github.com/ovn-org/libovsdb/ovsdb"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

func findLogicalSwitch(nbClient libovsdbclient.Client, name string) (string, error) {
	ls := []nbdb.LogicalSwitch{}
	err := nbClient.WhereCache(func(ls *nbdb.LogicalSwitch) bool {
		return ls.Name == name
	}).List(&ls)
	if err != nil {
		return "", fmt.Errorf("can't find logical switch: %v", err)
	}

	if len(ls) > 1 {
		return "", fmt.Errorf("unexpectedly found multiple logical switches: %+v", ls)
	}

	if len(ls) == 1 {
		return ls[0].UUID, nil
	}

	return "", nil
}

func AddACLsToLogicalSwitchOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, name string, acls ...*nbdb.ACL) ([]libovsdb.Operation, error) {
	if ops == nil {
		ops = []libovsdb.Operation{}
	}

	uuid, err := findLogicalSwitch(nbClient, name)
	if err != nil {
		return nil, err
	}

	if uuid == "" {
		return nil, fmt.Errorf("logical switch %s not found", name)
	}

	aclUUIDs := make([]string, 0, len(acls))
	for _, acl := range acls {
		aclUUIDs = append(aclUUIDs, acl.UUID)
	}

	ls := &nbdb.LogicalSwitch{UUID: uuid}
	op, err := nbClient.Where(ls).Mutate(ls, model.Mutation{
		Field:   &ls.ACLs,
		Mutator: libovsdb.MutateOperationInsert,
		Value:   aclUUIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("can't add ACL to logical switch op: %v", err)
	}
	ops = append(ops, op...)

	return ops, nil
}

func AddACLsToLogicalSwitch(nbClient libovsdbclient.Client, name string, acls ...*nbdb.ACL) error {
	ops, err := AddACLsToLogicalSwitchOps(nbClient, nil, name, acls...)
	if err != nil {
		return err
	}

	_, err = TransactAndCheck(nbClient, ops)
	return err
}
