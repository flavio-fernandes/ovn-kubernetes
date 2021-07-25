package libovsdbops

import (
	"fmt"
	"net"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/model"
	libovsdb "github.com/ovn-org/libovsdb/ovsdb"
	
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

func buildRouterNAT(
	natType nbdb.NATType,
	externalIP net.IP,
	logicalIP net.IP,
	logicalPort string,
	externalMac string,
	) *nbdb.NAT {
	return &nbdb.NAT{
		Type:            natType,
		ExternalIP:      externalIP.String(),
		LogicalIP:       logicalIP.String(),
		LogicalPort:     []string{logicalPort},
		ExternalMAC:     []string{externalMac},
		Options:         map[string]string{"stateless": "false"},
	}
}

func CreateOrUpdateLogicalRouterNAT(nbClient libovsdbclient.Client, routerName string,
	natType nbdb.NATType, externalIP net.IP, logicalIP net.IP, logicalPort string,
	externalMac string) error {

	ops := []libovsdb.Operation{}

	routers := []nbdb.LogicalRouter{}
	err := nbClient.WhereCache(func(item *nbdb.LogicalRouter) bool {
		return item.Name == routerName
	}).List(&routers)
	if err != nil {
		return fmt.Errorf("error finding logical router %s: %v", routerName, err)
	}
	if len(routers) == 0 {
		return fmt.Errorf("found no logical routers with name %s", routerName)
	}
	if len(routers) > 1 {
		return fmt.Errorf("unexpectedly found multiple logical routers: %+v", routers)
	}
	router := &routers[0]

	nats := []nbdb.NAT{}
	err = nbClient.WhereCache(func(item *nbdb.NAT) bool {
		return item.Type == natType && item.ExternalIP == externalIP.String()
	}).List(&nats)
	if err != nil {
		return fmt.Errorf("error finding NAT entries for type %s and IP %s: %v",
		natType, externalIP.String(), err)
	}

	// Locate NAT used by logical router, if there is one
	natIndex := -1
	for i := 0; natIndex == -1 && i < len(nats); i++ {
		for _, rtrNatUUID := range router.Nat {
			if nats[i].UUID == rtrNatUUID {
				natIndex = i
				break
			}
		}
	}

	if natIndex == -1 {
		nat := buildRouterNAT(natType, externalIP, logicalIP, logicalPort, externalMac)
		nat.UUID = "new_rtr_nat"
		op, err := nbClient.Create(nat)
		if err != nil {
			return fmt.Errorf("error creating NAT for logical router %s: %v", routerName, err)
		}
		ops = append(ops, op...)

		mutations := []model.Mutation{
			{Field: &router.Nat, Mutator: libovsdb.MutateOperationInsert, Value: []string{nat.UUID}},
		}
		mutateOp, err := nbClient.Where(router).Mutate(router, mutations...)
		if err != nil {
			return fmt.Errorf("error adding NAT to logical router %s: %v", routerName, err)
		}
		ops = append(ops, mutateOp...)
	} else {
		nat := buildRouterNAT(natType, externalIP, logicalIP, logicalPort, externalMac)
		op, err := nbClient.Where(&nats[natIndex]).Update(nat)
		if err != nil {
			return fmt.Errorf("error updating NAT for logical router %s: %v", routerName, err)
		}
		ops = append(ops, op...)
	}

	_, err = TransactAndCheck(nbClient, ops)
	return err
}
