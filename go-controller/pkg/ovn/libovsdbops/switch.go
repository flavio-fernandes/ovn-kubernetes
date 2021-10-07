package libovsdbops

import (
	"fmt"
	"net"
	"strings"
	"sync"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/model"
	libovsdb "github.com/ovn-org/libovsdb/ovsdb"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// findSwitch looks up the switch in the cache and sets the UUID
func findSwitch(nbClient libovsdbclient.Client, lswitch *nbdb.LogicalSwitch) error {
	if lswitch.UUID != "" && !IsNamedUUID(lswitch.UUID) {
		return nil
	}

	switches := []nbdb.LogicalSwitch{}
	err := nbClient.WhereCache(func(item *nbdb.LogicalSwitch) bool {
		return item.Name == lswitch.Name
	}).List(&switches)
	if err != nil {
		return fmt.Errorf("can't find switch %+v: %v", *lswitch, err)
	}

	if len(switches) > 1 {
		return fmt.Errorf("unexpectedly found multiple switches: %+v", switches)
	}

	if len(switches) == 0 {
		return libovsdbclient.ErrNotFound
	}

	lswitch.UUID = switches[0].UUID
	return nil
}

// FindSwitch Looks up switches in the cache based on the lookup function
func FindSwitch(nbClient libovsdbclient.Client, lookupFunction func(item *nbdb.LogicalSwitch) bool) ([]nbdb.LogicalSwitch, error) {
	switches := []nbdb.LogicalSwitch{}

	err := nbClient.WhereCache(lookupFunction).List(&switches)
	if err != nil {
		return nil, fmt.Errorf("can't find switches: %v", err)
	}

	if len(switches) == 0 {
		return nil, libovsdbclient.ErrNotFound
	}

	return switches, nil
}

func AddLoadBalancersToSwitchOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, lswitch *nbdb.LogicalSwitch, lbs ...*nbdb.LoadBalancer) ([]libovsdb.Operation, error) {
	if ops == nil {
		ops = []libovsdb.Operation{}
	}
	if len(lbs) == 0 {
		return ops, nil
	}

	err := findSwitch(nbClient, lswitch)
	if err != nil {
		return nil, err
	}

	lbUUIDs := make([]string, 0, len(lbs))
	for _, lb := range lbs {
		lbUUIDs = append(lbUUIDs, lb.UUID)
	}

	op, err := nbClient.Where(lswitch).Mutate(lswitch, model.Mutation{
		Field:   &lswitch.LoadBalancer,
		Mutator: libovsdb.MutateOperationInsert,
		Value:   lbUUIDs,
	})
	if err != nil {
		return nil, err
	}
	ops = append(ops, op...)
	return ops, nil
}

func RemoveLoadBalancersFromSwitchOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, lswitch *nbdb.LogicalSwitch, lbs ...*nbdb.LoadBalancer) ([]libovsdb.Operation, error) {
	if ops == nil {
		ops = []libovsdb.Operation{}
	}
	if len(lbs) == 0 {
		return ops, nil
	}

	err := findSwitch(nbClient, lswitch)
	if err != nil {
		return nil, err
	}

	lbUUIDs := make([]string, 0, len(lbs))
	for _, lb := range lbs {
		lbUUIDs = append(lbUUIDs, lb.UUID)
	}

	op, err := nbClient.Where(lswitch).Mutate(lswitch, model.Mutation{
		Field:   &lswitch.LoadBalancer,
		Mutator: libovsdb.MutateOperationDelete,
		Value:   lbUUIDs,
	})
	if err != nil {
		return nil, err
	}
	ops = append(ops, op...)

	return ops, nil
}

func ListSwitchesWithLoadBalancers(nbClient libovsdbclient.Client) ([]nbdb.LogicalSwitch, error) {
	switches := &[]nbdb.LogicalSwitch{}
	err := nbClient.WhereCache(func(item *nbdb.LogicalSwitch) bool {
		return item.LoadBalancer != nil
	}).List(switches)
	return *switches, err
}

//TODO(astoycos) Question to reviewers do we need this lock anymore?
var updateNodeSwitchLock sync.Mutex

// UpdateNodeSwitchExcludeIPs should be called after adding the management port
// and after adding the hybrid overlay port, and ensures that each port's IP
// is added to the logical switch's exclude_ips. This prevents ovn-northd log
// spam about duplicate IP addresses.
// See https://github.com/ovn-org/ovn-kubernetes/pull/779
func UpdateNodeSwitchExcludeIPs(modelClient ModelClient, nodeName string, subnet *net.IPNet) error {
	if utilnet.IsIPv6CIDR(subnet) {
		// We don't exclude any IPs in IPv6
		return nil
	}

	nbClient := modelClient.GetClient()

	updateNodeSwitchLock.Lock()
	defer updateNodeSwitchLock.Unlock()

	lsps := []nbdb.LogicalSwitchPort{}
	// Only Query The cache for mp0 and HO LSPs
	if err := nbClient.WhereCache(func(item *nbdb.LogicalSwitchPort) bool {
		return strings.Contains(item.Name, types.K8sPrefix+nodeName) ||
			strings.Contains(item.Name, types.HybridOverlayPrefix+nodeName)
	}).List(&lsps); err != nil {
		return fmt.Errorf("failed to list all logical_switch_ports error: %v", err)
	}

	var haveManagementPort, haveHybridOverlayPort bool
	switch len(lsps) {
	case 0:
		haveManagementPort = false
		haveHybridOverlayPort = false
	case 1:
		if strings.Contains(lsps[0].Name, types.K8sPrefix+nodeName) {
			haveManagementPort = true

		}
		if strings.Contains(lsps[0].Name, types.HybridOverlayPrefix+nodeName) {
			haveHybridOverlayPort = true
		}
	case 2:
		haveManagementPort = true
		haveHybridOverlayPort = true
	}

	mgmtIfAddr := util.GetNodeManagementIfAddr(subnet)
	hybridOverlayIfAddr := util.GetNodeHybridOverlayIfAddr(subnet)

	klog.V(5).Infof("haveMP %v haveHO %v ManagementPortAddress %v HybridOverlayAddressOA %v", haveManagementPort, haveHybridOverlayPort, mgmtIfAddr, hybridOverlayIfAddr)
	var excludeIPs string
	if config.HybridOverlay.Enabled {
		if haveHybridOverlayPort && haveManagementPort {
			// no excluded IPs required
		} else if !haveHybridOverlayPort && !haveManagementPort {
			// exclude both
			excludeIPs = mgmtIfAddr.IP.String() + ".." + hybridOverlayIfAddr.IP.String()
		} else if haveHybridOverlayPort {
			// exclude management port IP
			excludeIPs = mgmtIfAddr.IP.String()
		} else if haveManagementPort {
			// exclude hybrid overlay port IP
			excludeIPs = hybridOverlayIfAddr.IP.String()
		}
	} else if !haveManagementPort {
		// exclude management port IP
		excludeIPs = mgmtIfAddr.IP.String()
	}

	logicalSwitchDes := nbdb.LogicalSwitch{
		Name:        nodeName,
		OtherConfig: map[string]string{"exclude_ips": excludeIPs},
	}

	opModels := []OperationModel{
		{
			Model:          &logicalSwitchDes,
			ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == nodeName },
			OnModelMutations: []interface{}{
				&logicalSwitchDes.OtherConfig,
			},
			ErrNotFound: true,
		},
	}

	if len(excludeIPs) == 0 {
		if err := modelClient.Delete(opModels...); err != nil {
			return fmt.Errorf("failed to delete otherConfig:exclude_ips from logical switch %s, error: %v", nodeName, err)
		}
	}

	if len(excludeIPs) > 0 {
		if _, err := modelClient.CreateOrUpdate(opModels...); err != nil {
			return fmt.Errorf("failed to configure otherConfig:exclude_ips from logical switch %s, error: %v", nodeName, err)
		}
	}

	return nil
}

// RemoveACLFromSwitches removes the ACL uuid entry from Logical Switch acl's list.
func RemoveACLFromSwitches(modelClient ModelClient, switches []nbdb.LogicalSwitch, aclUUID string) error {
	var opModels []OperationModel
	for i, sw := range switches {
		sw.ACLs = []string{aclUUID}
		swName := switches[i].Name
		opModels = append(opModels, OperationModel{
			Model:          &sw,
			ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == swName },
			OnModelMutations: []interface{}{
				&sw.ACLs,
			},
			ErrNotFound: true,
			BulkOp:      true,
		})
	}

	if err := modelClient.Delete(opModels...); err != nil {
		return fmt.Errorf("error while removing ACL: %s, from switches err: %v", aclUUID, err)
	}

	return nil
}
