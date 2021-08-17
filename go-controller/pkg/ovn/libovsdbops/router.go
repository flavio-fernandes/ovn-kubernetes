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
	externalIP string,
	logicalIP string,
	logicalPort string,
	externalMac string,
	externalIDs *map[string]string,
) *nbdb.NAT {
	nat := &nbdb.NAT{
		Type:       natType,
		ExternalIP: externalIP,
		LogicalIP:  logicalIP,
		Options:    map[string]string{"stateless": "false"},
	}

	if logicalPort != "" {
		nat.LogicalPort = &logicalPort
	}

	if externalMac != "" {
		nat.ExternalMAC = &externalMac
	}

	if externalIDs != nil {
		nat.ExternalIDs = *externalIDs
	}

	return nat
}

func BuildRouterSNAT(
	externalIP *net.IP,
	logicalIP *net.IPNet,
	logicalPort string,
	externalIDs *map[string]string,
) (*nbdb.NAT, error) {
	if logicalIP == nil {
		return nil, fmt.Errorf("logicalIP cannot be nil when building SNAT")
	}
	externalIPStr := ""
	if externalIP != nil {
		externalIPStr = externalIP.String()
	}
	// Strip out mask of logicalIP only if it is a host mask
	logicalIPMask, _ := logicalIP.Mask.Size()
	logicalIPStr := logicalIP.IP.String()
	if logicalIPMask != 32 && logicalIPMask != 128 {
		logicalIPStr = logicalIP.String()
	}
	return buildRouterNAT(nbdb.NATTypeSNAT, externalIPStr, logicalIPStr, logicalPort, "", externalIDs), nil
}

func BuildRouterDNATAndSNAT(
	externalIP *net.IP,
	logicalIP *net.IPNet,
	logicalPort string,
	externalMac string,
	externalIDs *map[string]string,
) (*nbdb.NAT, error) {
	if externalIP == nil && logicalPort == "" {
		return nil, fmt.Errorf("externalIP cannot be nil when building DNAT types w/out logicalPort")
	}
	externalIPStr := ""
	if externalIP != nil {
		externalIPStr = externalIP.String()
	}
	logicalIPStr := ""
	if logicalIP != nil {
		logicalIPStr = logicalIP.IP.String()
	}
	return buildRouterNAT(
		nbdb.NATTypeDNATAndSNAT,
		externalIPStr,
		logicalIPStr,
		logicalPort,
		externalMac,
		externalIDs),
		nil
}

func isEquivalentNAT(existing *nbdb.NAT, searched *nbdb.NAT) bool {
	// Simple case: uuid was provided.
	if searched.UUID != "" && existing.UUID == searched.UUID {
		return true
	}

	if searched.Type != existing.Type {
		return false
	}

	// If searching based on type and logicalPort, no need to look any further.
	if searched.LogicalPort != nil {
		return existing.LogicalPort != nil && *searched.LogicalPort == *existing.LogicalPort
	}

	// Allow externalIP to be empty if type is SNAT.
	if (searched.ExternalIP != "" || searched.Type != nbdb.NATTypeSNAT) &&
		searched.ExternalIP != existing.ExternalIP {
			return false
	}

	// Compare logicalIP only for SNAT, since DNAT types must have unique ExternalIP.
	if searched.Type == nbdb.NATTypeSNAT && searched.LogicalIP != existing.LogicalIP {
		return false
	}

    for externalIdKey, externalIdValue := range searched.ExternalIDs {
        if foundValue, found := existing.ExternalIDs[externalIdKey]; !found || foundValue != externalIdValue {
            return false
        }
    }

	return true
}

func findRouter(nbClient libovsdbclient.Client, routerName string) (*nbdb.LogicalRouter, error) {
	routers := []nbdb.LogicalRouter{}
	err := nbClient.WhereCache(func(item *nbdb.LogicalRouter) bool {
		return item.Name == routerName
	}).List(&routers)

	if err != nil {
		return nil, fmt.Errorf("error finding logical router %s: %v", routerName, err)
	}

	if len(routers) == 0 {
		return nil, fmt.Errorf("found no logical routers with name %s", routerName)
	}

	if len(routers) > 1 {
		return nil, fmt.Errorf("unexpectedly found multiple logical routers: %+v", routers)
	}

	return &routers[0], nil
}


func getRouterNats(nbClient libovsdbclient.Client, router *nbdb.LogicalRouter) ([]nbdb.NAT, error) {
	nats := []nbdb.NAT{}

	var err error
	var nat *nbdb.NAT
	for _, rtrNatUUID := range router.Nat {
		nat = &nbdb.NAT{UUID: rtrNatUUID}
		err = nbClient.Get(nat)
		if err != nil {
			return nil, err
		}
		nats = append(nats, *nat)
	}

	return nats, nil
}

func addOrUpdateNatToRouterOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, router *nbdb.LogicalRouter, routerNats []nbdb.NAT, nat nbdb.NAT) ([]libovsdb.Operation, error) {
	if ops == nil {
		ops = []libovsdb.Operation{}
	}

	// Find out if NAT is already listed in the logical router.
	natIndex := -1
	for i := 0; natIndex == -1 && i < len(routerNats); i++ {
		if isEquivalentNAT(&routerNats[i], &nat) {
			natIndex = i
			break
		}
	}

	if natIndex == -1 {
		nat.UUID = buildNamedUUID(fmt.Sprintf("nat_%s_%s_%s", nat.Type, nat.ExternalIP, nat.LogicalIP))

		op, err := nbClient.Create(&nat)
		if err != nil {
			return nil, fmt.Errorf("error creating NAT %s for logical router %s %#v : %v", nat.UUID, router.Name, nat, err)
		}
		ops = append(ops, op...)

		mutations := []model.Mutation{
			{
				Field:   &router.Nat,
				Mutator: libovsdb.MutateOperationInsert,
				Value:   []string{nat.UUID},
			},
		}
		mutateOp, err := nbClient.Where(router).Mutate(router, mutations...)
		if err != nil {
			return ops, err
		}
		ops = append(ops, mutateOp...)
	} else {
		op, err := nbClient.Where(
			&nbdb.NAT{
				UUID: routerNats[natIndex].UUID,
			}).Update(&nat)
		if err != nil {
			return nil, fmt.Errorf("error updating NAT %s for logical router %s: %v", routerNats[natIndex].UUID, router.Name, err)
		}
		ops = append(ops, op...)
	}

	return ops, nil
}

func AddOrUpdateNatsToRouterOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, routerName string, nats ...*nbdb.NAT) ([]libovsdb.Operation, error) {
	router, err := findRouter(nbClient, routerName)
	if err != nil {
		return nil, err
	}

	routerNats, err := getRouterNats(nbClient, router)
	if err != nil {
		return nil, err
	}

	for _, nat := range nats {
		if nat != nil {
			ops, err = addOrUpdateNatToRouterOps(nbClient, ops, router, routerNats, *nat)
			if err != nil {
				return nil, err
			}
		}
	}

	return ops, nil
}

func DeleteNatsFromRouterOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, routerName string, nats ...*nbdb.NAT) ([]libovsdb.Operation, error) {
	router, err := findRouter(nbClient, routerName)
	if err != nil {
		return nil, err
	}

	routerNats, err := getRouterNats(nbClient, router)
	if err != nil {
		return nil, err
	}

	natUUIDs := make([]string, 0, len(nats))
	for _, nat := range nats {
		if nat == nil {
			continue
		}
		for i := 0; i < len(routerNats); i++ {
			if isEquivalentNAT(&routerNats[i], nat) {
				natUUIDs = append(natUUIDs, routerNats[i].UUID)
				break
			}
		}
	}

	if len(natUUIDs) > 0 {
		if ops == nil {
			ops = []libovsdb.Operation{}
		}
	
		mutations := []model.Mutation{
			{
				Field:   &router.Nat,
				Mutator: libovsdb.MutateOperationDelete,
				Value:   natUUIDs,
			},
		}
		mutateOp, err := nbClient.Where(router).Mutate(router, mutations...)
		if err != nil {
			return ops, err
		}
		ops = append(ops, mutateOp...)
	}

	return ops, nil
}

func AddOrUpdateNatsToRouter(nbClient libovsdbclient.Client, routerName string, nats ...*nbdb.NAT) error {
	ops, err := AddOrUpdateNatsToRouterOps(nbClient, nil, routerName, nats...)
	if err != nil {
		return err
	}

	_, err = TransactAndCheck(nbClient, ops)
	return err
}

func DeleteNatsFromRouter(nbClient libovsdbclient.Client, routerName string, nats ...*nbdb.NAT) error {
	ops, err := DeleteNatsFromRouterOps(nbClient, nil, routerName, nats...)
	if err != nil {
		return err
	}

	_, err = TransactAndCheck(nbClient, ops)
	return err
}
