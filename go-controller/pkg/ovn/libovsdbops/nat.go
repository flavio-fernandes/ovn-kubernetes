package libovsdbops

import (
	"fmt"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	libovsdb "github.com/ovn-org/libovsdb/ovsdb"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

func BuildNAT(uuid, allowedExtIPs, exemptedExtIPs, externalIP string, externalIds map[string]string) *nbdb.NAT {
	return &nbdb.NAT{
		UUID:            uuid,
		AllowedExtIPs:   []string{allowedExtIPs},
		ExemptedExtIPs:  []string{exemptedExtIPs},
		ExternalIDs:     externalIds,
		ExternalIP:      externalIP,
	}
}

func CreateOrUpdateLogicalRouterNAT(nbClient libovsdbclient.Client) error {
	//var err error
	ops := []libovsdb.Operation{}

	lss := []nbdb.LogicalSwitch{}
	err := nbClient.WhereCache(func(item *nbdb.LogicalSwitch) bool {
		return item.Name == "foo"
	}).List(&lss)
	if err != nil {
		return fmt.Errorf("error finding logical switches: %v", err)
	}

	if len(lss) == 0 {
		externalIds := map[string]string{"count": "1"}
		foo := &nbdb.LogicalSwitch{Name:"foo", ExternalIDs:externalIds}
		op, err := nbClient.Create(foo)
		if err != nil {
			return err
		}
		ops = append(ops, op...)
	}

	_, err = TransactAndCheck(nbClient, ops)
	return err
}
