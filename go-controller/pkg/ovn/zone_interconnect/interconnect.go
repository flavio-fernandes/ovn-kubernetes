package zoneinterconnect

import (
	"fmt"
	"net"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	libovsdbclient "github.com/ovn-org/libovsdb/client"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/sbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

const (
	transitSwitchTunnelKey = "16711683"
)

type ZoneInterconnectHandler struct {
	util.NetInfo
	nbClient                 libovsdbclient.Client
	sbClient                 libovsdbclient.Client
	networkClusterRouterName string
	networkTransitSwitchName string
}

func NewZoneInterconnectHandler(nInfo util.NetInfo, nbClient, sbClient libovsdbclient.Client) *ZoneInterconnectHandler {
	zic := &ZoneInterconnectHandler{
		NetInfo:  nInfo,
		nbClient: nbClient,
		sbClient: sbClient,
	}

	zic.networkClusterRouterName = zic.getNetworkScopedName(types.OVNClusterRouter)
	zic.networkTransitSwitchName = zic.getNetworkScopedName(types.TransitSwitch)

	return zic
}

// AddLocalZoneNode creates the interconnect resources in OVN NB DB for the local zone node
func (zic *ZoneInterconnectHandler) AddLocalZoneNode(node *corev1.Node) error {
	klog.Infof("Creating interconnect resources for local zone node [%s] for the network [%s]", node.Name, zic.GetNetworkName())
	nodeId := util.GetNodeId(node)
	if nodeId == -1 {
		// Don't consider this node as cluster-manager has not allocated node id yet.
		return fmt.Errorf("failed to get node id for node - %s", node.Name)
	}

	if err := zic.createLocalZoneNodeResources(node, nodeId); err != nil {
		klog.Errorf("Creating interconnect resources for local zone node [%s] for the network [%s] failed : err - %v", node.Name, zic.GetNetworkName(), err)
		return fmt.Errorf("creating interconnect resources for local zone node [%s] for the network [%s] failed : err - %v", node.Name, zic.GetNetworkName(), err)
	}

	return nil
}

// AddRemoteZoneNode creates the interconnect resources in OVN NB DB for the remote zone node
func (zic *ZoneInterconnectHandler) AddRemoteZoneNode(node *corev1.Node) error {
	klog.Infof("Creating interconnect resources for remote zone node [%s] for the network [%s]", node.Name, zic.GetNetworkName())

	nodeId := util.GetNodeId(node)
	if nodeId == -1 {
		// Don't consider this node as cluster-manager has not allocated node id yet.
		return fmt.Errorf("failed to get node id for node - %s", node.Name)
	}

	// Get the chassis id.
	chassisId, err := util.ParseNodeChassisIDAnnotation(node)
	if err != nil {
		return fmt.Errorf("failed to parse node chassis-id for node - %s, error: %v", node.Name, err)
	}

	if err := zic.createRemoteZoneNodeResources(node, nodeId, chassisId); err != nil {
		klog.Errorf("Creating interconnect resources for remote zone node [%s] for the network [%s] failed : err - %v", node.Name, zic.GetNetworkName(), err)
		return fmt.Errorf("creating interconnect resources for remote zone node [%s] for the network [%s] failed : err - %v", node.Name, zic.GetNetworkName(), err)
	}

	return nil
}

// DeleteNode deletes the local zone node or remote zone node resources
func (zic *ZoneInterconnectHandler) DeleteNode(node *corev1.Node) error {
	klog.Infof("Deleting interconnect resources for the node [%s] for the network [%s]", node.Name, zic.GetNetworkName())

	// Cleanup the logical router port in the cluster router for the node
	// if it exists.
	if err := zic.cleanupNodeClusterRouterPort(node); err != nil {
		return err
	}

	// Cleanup the logical switch port in the transit switch for the node
	// if it exists.
	return zic.cleanupNodeTransitSwitchPort(node)
}

func (zic *ZoneInterconnectHandler) createLocalZoneNodeResources(node *corev1.Node, nodeId int) error {
	nodeTransitSwitchPortIps, err := util.ParseNodeTransitSwitchPortAddresses(node)
	if err != nil || len(nodeTransitSwitchPortIps) == 0 {
		return fmt.Errorf("failed to get the node transit switch port ips for node %s: %v", node.Name, err)
	}

	var transitRouterPortMac net.HardwareAddr
	var transitRouterPortNetworks []string
	var transitRouterPortIps []string
	foundIPv4 := false
	for _, ip := range nodeTransitSwitchPortIps {
		if utilnet.IsIPv4CIDR(ip) {
			foundIPv4 = true
			transitRouterPortMac = util.IPAddrToHWAddr(ip.IP)
		} else {
			if !foundIPv4 {
				transitRouterPortMac = util.IPAddrToHWAddr(ip.IP)
			}
		}
		transitRouterPortNetworks = append(transitRouterPortNetworks, ip.String())
		transitRouterPortIps = append(transitRouterPortIps, ip.IP.String())
	}

	ts := &nbdb.LogicalSwitch{
		Name: zic.networkTransitSwitchName,
	}

	_, err = libovsdbops.GetLogicalSwitch(zic.nbClient, ts)
	if err != nil {
		// Create transit switch
		ts.OtherConfig = map[string]string{
			"interconn-ts":             zic.networkTransitSwitchName,
			"requested-tnl-key":        transitSwitchTunnelKey,
			"mcast_snoop":              "true",
			"mcast_flood_unregistered": "true",
		}
		if err := libovsdbops.CreateOrUpdateLogicalSwitch(zic.nbClient, ts); err != nil {
			return fmt.Errorf("failed to create/update logical transit switch: %v", err)
		}
	}

	// Connect transit switch to the cluster router by creating a pair of logical switch port - logical router port
	logicalRouterPortName := zic.getNetworkScopedName(types.RouterToTransitSwitchPrefix + node.Name)
	logicalRouterPort := nbdb.LogicalRouterPort{
		Name:     logicalRouterPortName,
		MAC:      transitRouterPortMac.String(),
		Networks: transitRouterPortNetworks,
		Options: map[string]string{
			"mcast_flood": "true",
		},
	}
	logicalRouter := nbdb.LogicalRouter{
		Name: zic.networkClusterRouterName,
	}

	if err := libovsdbops.CreateOrUpdateLogicalRouterPort(zic.nbClient, &logicalRouter,
		&logicalRouterPort, nil); err != nil {
		return fmt.Errorf("failed to create/update cluster router %s to add transit switch port %s for the node %s: %v", zic.networkClusterRouterName, logicalRouterPortName, node.Name, err)
	}

	lspOptions := map[string]string{
		"router-port":       logicalRouterPortName,
		"requested-tnl-key": strconv.Itoa(nodeId),
	}

	err = zic.addNodeLogicalSwitchPort(zic.networkTransitSwitchName, zic.getNetworkScopedName(types.TransitSwitchToRouterPrefix+node.Name),
		"router", []string{"router"}, lspOptions)
	if err != nil {
		return err
	}

	// Its possible that node is moved from a remote zone to the local zone. Check and delete the remote zone routes
	// for this node as it's no longer needed.
	return zic.deleteLocalNodeStaticRoutes(node, nodeId, transitRouterPortIps)
}

func (zic *ZoneInterconnectHandler) createRemoteZoneNodeResources(node *corev1.Node, nodeId int, chassisId string) error {
	nodeTransitSwitchPortIps, err := util.ParseNodeTransitSwitchPortAddresses(node)
	if err != nil || len(nodeTransitSwitchPortIps) == 0 {
		return fmt.Errorf("failed to get the node transit switch port Ips : %v", err)
	}

	ts := &nbdb.LogicalSwitch{
		Name: zic.networkTransitSwitchName,
	}

	_, err = libovsdbops.GetLogicalSwitch(zic.nbClient, ts)
	if err != nil {
		// Create transit switch
		ts.OtherConfig = map[string]string{
			"interconn-ts":             zic.networkTransitSwitchName,
			"requested-tnl-key":        transitSwitchTunnelKey,
			"mcast_snoop":              "true",
			"mcast_flood_unregistered": "true",
		}
		if err := libovsdbops.CreateOrUpdateLogicalSwitch(zic.nbClient, ts); err != nil {
			return fmt.Errorf("failed to create/update logical transit switch: %v", err)
		}
	}

	var transitRouterPortMac net.HardwareAddr
	var transitRouterPortNetworks []string
	var transitRouterPortIps []string
	foundIPv4 := false
	for _, ip := range nodeTransitSwitchPortIps {
		if utilnet.IsIPv4CIDR(ip) {
			foundIPv4 = true
			transitRouterPortMac = util.IPAddrToHWAddr(ip.IP)
		} else {
			if !foundIPv4 {
				transitRouterPortMac = util.IPAddrToHWAddr(ip.IP)
			}
		}
		transitRouterPortNetworks = append(transitRouterPortNetworks, ip.String())
		transitRouterPortIps = append(transitRouterPortIps, ip.IP.String())
	}

	remotePortAddr := transitRouterPortMac.String()
	for _, tsNetwork := range transitRouterPortNetworks {
		remotePortAddr = remotePortAddr + " " + tsNetwork
	}

	lspOptions := map[string]string{
		"requested-tnl-key": strconv.Itoa(nodeId),
	}
	remotePortName := zic.getNetworkScopedName(types.TransitSwitchToRouterPrefix + node.Name)
	if err := zic.addNodeLogicalSwitchPort(zic.networkTransitSwitchName, remotePortName, "remote", []string{remotePortAddr}, lspOptions); err != nil {
		return err
	}
	// Set the port binding chassis.
	if err := zic.setRemotePortBindingChassis(node.Name, remotePortName, chassisId); err != nil {
		return err
	}

	if err := zic.addRemoteNodeStaticRoutes(node, nodeId, transitRouterPortIps); err != nil {
		return err
	}

	// Cleanup the logical router port connecting to the transit switch for the remote node (if present)
	// Cleanup would be required when a local zone node moves to a remote zone.
	return zic.cleanupNodeClusterRouterPort(node)
}

func (zic *ZoneInterconnectHandler) addNodeLogicalSwitchPort(logicalSwitchName, portName, portType string, addresses []string, options map[string]string) error {
	logicalSwitch := nbdb.LogicalSwitch{
		Name: logicalSwitchName,
	}

	logicalSwitchPort := nbdb.LogicalSwitchPort{
		Name:      portName,
		Type:      portType,
		Options:   options,
		Addresses: addresses,
	}
	if err := libovsdbops.CreateOrUpdateLogicalSwitchPortsOnSwitch(zic.nbClient, &logicalSwitch, &logicalSwitchPort); err != nil {
		return fmt.Errorf("failed to add logical port %s to switch %s, error: %v", portName, logicalSwitch.Name, err)
	}
	return nil
}

func (zic *ZoneInterconnectHandler) cleanupNodeClusterRouterPort(node *corev1.Node) error {
	lrp := nbdb.LogicalRouterPort{
		Name: zic.getNetworkScopedName(types.RouterToTransitSwitchPrefix + node.Name),
	}
	logicalRouterPort, err := libovsdbops.GetLogicalRouterPort(zic.nbClient, &lrp)
	if err != nil {
		// logical router port doesn't exist. So nothing to cleanup.
		return nil
	}

	logicalRouter := nbdb.LogicalRouter{
		Name: zic.networkClusterRouterName,
	}

	if err := libovsdbops.DeleteLogicalRouterPorts(zic.nbClient, &logicalRouter, logicalRouterPort); err != nil {
		return fmt.Errorf("failed to delete logical router port %s from router %s for the node %s, error: %v", logicalRouterPort.Name, zic.networkClusterRouterName, node.Name, err)
	}

	return nil
}

func (zic *ZoneInterconnectHandler) cleanupNodeTransitSwitchPort(node *corev1.Node) error {
	logicalSwitch := &nbdb.LogicalSwitch{
		Name: zic.networkTransitSwitchName,
	}
	logicalSwitchPort := &nbdb.LogicalSwitchPort{
		Name: zic.getNetworkScopedName(types.TransitSwitchToRouterPrefix + node.Name),
	}

	if err := libovsdbops.DeleteLogicalSwitchPorts(zic.nbClient, logicalSwitch, logicalSwitchPort); err != nil {
		return fmt.Errorf("failed to delete logical switch port %s from transit switch %s for the node %s, error: %v", logicalSwitchPort.Name, zic.networkTransitSwitchName, node.Name, err)
	}
	return nil
}

func (zic *ZoneInterconnectHandler) setRemotePortBindingChassis(nodeName, portName, chassisId string) error {
	remotePort := sbdb.PortBinding{
		LogicalPort: portName,
	}
	chassis := sbdb.Chassis{
		Hostname: nodeName,
		Name:     chassisId,
	}

	if err := libovsdbops.UpdatePortBindingSetChassis(zic.sbClient, &remotePort, &chassis); err != nil {
		return fmt.Errorf("failed to update chassis %s for remote port %s, error: %v", nodeName, portName, err)
	}

	return nil
}

func (zic *ZoneInterconnectHandler) addRemoteNodeStaticRoutes(node *corev1.Node, nodeId int, tsIps []string) error {
	addRoute := func(subnet *net.IPNet, tsIp string) error {
		logicalRouterStaticRoute := nbdb.LogicalRouterStaticRoute{
			ExternalIDs: map[string]string{
				"ic-node": node.Name,
			},
			Nexthop:  tsIp,
			IPPrefix: subnet.String(),
		}
		p := func(lrsr *nbdb.LogicalRouterStaticRoute) bool {
			return lrsr.IPPrefix == subnet.String() &&
				lrsr.Nexthop == tsIp &&
				lrsr.ExternalIDs["ic-node"] == node.Name
		}
		//FIXME: All routes should be added in a single transaction instead.
		if err := libovsdbops.CreateOrReplaceLogicalRouterStaticRouteWithPredicate(zic.nbClient, zic.networkClusterRouterName, &logicalRouterStaticRoute, p); err != nil {
			return fmt.Errorf("failed to create static route: %v", err)
		}
		return nil
	}

	nodeSubnets, err := util.ParseNodeHostSubnetAnnotation(node, zic.GetNetworkName())
	if err != nil {
		return fmt.Errorf("failed to parse node %s subnets annotation %v", node.Name, err)
	}

	//FIXME: No consistency on transaction failure.
	for _, subnet := range nodeSubnets {
		for _, tsIp := range tsIps {
			if err := addRoute(subnet, tsIp); err != nil {
				return fmt.Errorf("unable to create static routes: %v", err)
			}
		}
	}

	if zic.IsSecondary() {
		// Secondary network cluster router doesn't connect to a join switch
		// or to a Gateway router.
		return nil
	}

	joinSubnets, err := util.ParseZoneJoinSubnetsAnnotation(node, zic.GetNetworkName())
	if err != nil {
		return fmt.Errorf("failed to parse node %s join subnets annotation %v", node.Name, err)
	}

	for _, subnet := range joinSubnets {
		for _, tsIp := range tsIps {
			if err := addRoute(subnet, tsIp); err != nil {
				return fmt.Errorf("unable to create static routes: %v", err)
			}
		}
	}

	nodeGRIPs, err := util.ParseNodeGRIPsAnnotation(node)
	if err != nil {

		return fmt.Errorf("failed to parse node %s GR IPs annotation %v", node.Name, err)
	}

	for _, subnet := range nodeGRIPs {
		for _, tsIp := range tsIps {
			if err := addRoute(subnet, tsIp); err != nil {
				return fmt.Errorf("unable to create static routes: %v", err)
			}
		}
	}

	return nil
}

func (zic *ZoneInterconnectHandler) deleteLocalNodeStaticRoutes(node *corev1.Node, nodeId int, tsIps []string) error {
	deleteRoute := func(subnet *net.IPNet, tsIp string) error {
		p := func(lrsr *nbdb.LogicalRouterStaticRoute) bool {
			return lrsr.IPPrefix == subnet.String() &&
				lrsr.Nexthop == tsIp &&
				lrsr.ExternalIDs["ic-node"] == node.Name
		}
		//FIXME: All routes should be added in a single transaction instead.
		if err := libovsdbops.DeleteLogicalRouterStaticRoutesWithPredicate(zic.nbClient, zic.networkClusterRouterName, p); err != nil {
			return fmt.Errorf("failed to delete static route: %v", err)
		}
		return nil
	}

	nodeSubnets, err := util.ParseNodeHostSubnetAnnotation(node, zic.GetNetworkName())
	if err != nil {
		return fmt.Errorf("failed to parse node %s subnets annotation %v", node.Name, err)
	}

	//FIXME: No consistency on transaction failure.
	for _, subnet := range nodeSubnets {
		for _, tsIp := range tsIps {
			if err := deleteRoute(subnet, tsIp); err != nil {
				return fmt.Errorf("unable to create static routes: %v", err)
			}
		}
	}

	if zic.IsSecondary() {
		// Secondary network cluster router doesn't connect to a join switch
		// or to a Gateway router.
		return nil
	}

	joinSubnets, err := util.ParseZoneJoinSubnetsAnnotation(node, zic.GetNetworkName())
	if err != nil {
		return fmt.Errorf("failed to parse node %s join subnets annotation %v", node.Name, err)
	}

	for _, subnet := range joinSubnets {
		for _, tsIp := range tsIps {
			if err := deleteRoute(subnet, tsIp); err != nil {
				return fmt.Errorf("unable to create static routes: %v", err)
			}
		}
	}

	// Clear the routes connecting to the GW Router for the default network
	nodeGRIPs, err := util.ParseNodeGRIPsAnnotation(node)
	if err != nil {
		return fmt.Errorf("failed to parse node %s GR IPs annotation %v", node.Name, err)
	}

	for _, subnet := range nodeGRIPs {
		for _, tsIp := range tsIps {
			if err := deleteRoute(subnet, tsIp); err != nil {
				return fmt.Errorf("unable to create static routes: %v", err)
			}
		}
	}

	return nil
}

func (zic *ZoneInterconnectHandler) getNetworkScopedName(name string) string {
	return fmt.Sprintf("%s%s", zic.GetPrefix(), name)
}
