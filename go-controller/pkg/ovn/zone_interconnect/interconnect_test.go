package zoneinterconnect

import (
	"fmt"
	"sort"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/urfave/cli/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	ovncnitypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/sbdb"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

func newClusterJoinSwitch() *nbdb.LogicalSwitch {
	return &nbdb.LogicalSwitch{
		UUID: types.OVNJoinSwitch + "-UUID",
		Name: types.OVNJoinSwitch,
	}
}

func newOVNClusterRouter(netName string) *nbdb.LogicalRouter {
	return &nbdb.LogicalRouter{
		UUID: getNetworkScopedName(netName, types.OVNClusterRouter) + "-UUID",
		Name: getNetworkScopedName(netName, types.OVNClusterRouter),
	}
}

func createTransitSwitchPortBindings(sbClient libovsdbclient.Client, netName string, nodes ...*v1.Node) error {
	for _, node := range nodes {
		pb := sbdb.PortBinding{
			LogicalPort: getNetworkScopedName(netName, types.TransitSwitchToRouterPrefix+node.Name),
		}

		err := libovsdbops.CreatePortBinding(sbClient, &pb)
		if err != nil {
			return err
		}
	}

	return nil
}

func getNetworkScopedName(netName, name string) string {
	if netName == types.DefaultNetworkName {
		return fmt.Sprintf("%s", name)
	}
	return fmt.Sprintf("%s%s", util.GetSecondaryNetworkPrefix(netName), name)
}

func invokeICHandlerAddNodeFunction(zone string, icHandler *ZoneInterconnectHandler, nodes ...*v1.Node) error {
	for _, node := range nodes {
		if util.GetNodeZone(node) == zone {
			err := icHandler.AddLocalZoneNode(node)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		} else {
			err := icHandler.AddRemoteZoneNode(node)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}
	}

	return nil
}

func checkInterconnectResources(zone string, netName string, nbClient libovsdbclient.Client, nodes ...*v1.Node) error {
	localZoneNodes := []*v1.Node{}
	remoteZoneNodes := []*v1.Node{}
	localZoneNodeNames := []string{}
	remoteZoneNodeNames := []string{}
	for _, node := range nodes {
		nodeZone := util.GetNodeZone(node)
		if nodeZone == zone {
			localZoneNodes = append(localZoneNodes, node)
			localZoneNodeNames = append(localZoneNodeNames, node.Name)
		} else {
			remoteZoneNodes = append(remoteZoneNodes, node)
			remoteZoneNodeNames = append(remoteZoneNodeNames, node.Name)
		}

	}

	sort.Strings(localZoneNodeNames)
	sort.Strings(remoteZoneNodeNames)
	// First check if transit switch exists or not
	s := nbdb.LogicalSwitch{
		Name: getNetworkScopedName(netName, types.TransitSwitch),
	}

	ts, err := libovsdbops.GetLogicalSwitch(nbClient, &s)

	if err != nil {
		return fmt.Errorf("could not find transit switch %s in the nb db for network %s : err - %v", s.Name, netName, err)
	}

	noOfTSPorts := len(localZoneNodes) + len(remoteZoneNodes)

	if len(ts.Ports) != noOfTSPorts {
		return fmt.Errorf("transit switch %s doesn't have expected logical ports.  Found %d : Expected %d ports",
			getNetworkScopedName(netName, types.TransitSwitch), len(ts.Ports), noOfTSPorts)
	}
	// Checking just to be sure that the returned switch is infact transit switch.
	if ts.Name != getNetworkScopedName(netName, types.TransitSwitch) {
		return fmt.Errorf("transit switch %s not found in NB DB. Instead found %s", getNetworkScopedName(netName, types.TransitSwitch), ts.Name)
	}

	tsPorts := make([]string, noOfTSPorts)
	i := 0
	for _, p := range ts.Ports {
		lp := nbdb.LogicalSwitchPort{
			UUID: p,
		}

		lsp, err := libovsdbops.GetLogicalSwitchPort(nbClient, &lp)
		if err != nil {
			return fmt.Errorf("could not find logical switch port with uuid %s in the nb db for network %s : err - %v", p, netName, err)
		}
		tsPorts[i] = lsp.Name + ":" + lsp.Type
		i++
	}

	sort.Strings(tsPorts)

	// Verify Transit switch ports.
	// For local nodes, the transit switch port should be of type 'router'
	// and for remote zone nodes, it should be of type 'remote'.
	expectedTsPorts := make([]string, noOfTSPorts)
	i = 0
	for _, node := range localZoneNodes {
		// The logical port for the local zone nodes should be of type patch.
		nodeTSPortName := getNetworkScopedName(netName, types.TransitSwitchToRouterPrefix+node.Name)
		expectedTsPorts[i] = nodeTSPortName + ":router"
		i++
	}

	for _, node := range remoteZoneNodes {
		// The logical port for the local zone nodes should be of type patch.
		nodeTSPortName := getNetworkScopedName(netName, types.TransitSwitchToRouterPrefix+node.Name)
		expectedTsPorts[i] = nodeTSPortName + ":remote"
		i++
	}

	sort.Strings(expectedTsPorts)
	gomega.Expect(tsPorts).To(gomega.Equal(expectedTsPorts))

	r := nbdb.LogicalRouter{
		Name: getNetworkScopedName(netName, types.OVNClusterRouter),
	}

	clusterRouter, err := libovsdbops.GetLogicalRouter(nbClient, &r)
	if err != nil {
		return fmt.Errorf("could not find cluster router %s in the nb db for network %s : err - %v", r.Name, netName, err)
	}

	// Verify that the OVN cluster router ports for each local node
	// connects to the Transit switch.
	icClusterRouterPorts := []string{}
	lrpPrefixName := getNetworkScopedName(netName, types.RouterToTransitSwitchPrefix)
	for _, p := range clusterRouter.Ports {
		lp := nbdb.LogicalRouterPort{
			UUID: p,
		}

		lrp, err := libovsdbops.GetLogicalRouterPort(nbClient, &lp)
		if err != nil {
			return fmt.Errorf("could not find logical router port with uuid %s in the nb db for network %s : err - %v", p, netName, err)
		}

		if lrp.Name[:len(lrpPrefixName)] == lrpPrefixName {
			icClusterRouterPorts = append(icClusterRouterPorts, lrp.Name)
		}
	}

	sort.Strings(icClusterRouterPorts)

	expectedICClusterRouterPorts := []string{}
	for _, node := range localZoneNodes {
		expectedICClusterRouterPorts = append(expectedICClusterRouterPorts, getNetworkScopedName(netName, types.RouterToTransitSwitchPrefix+node.Name))
	}
	sort.Strings(expectedICClusterRouterPorts)

	gomega.Expect(icClusterRouterPorts).To(gomega.Equal(expectedICClusterRouterPorts))

	return nil
}

var _ = ginkgo.Describe("Zone Interconnect Operations", func() {
	var (
		app             *cli.App
		libovsdbCleanup *libovsdbtest.Cleanup
		testNode1       v1.Node
		testNode2       v1.Node
		testNode3       v1.Node
		node1Chassis    sbdb.Chassis
		node2Chassis    sbdb.Chassis
		node3Chassis    sbdb.Chassis
		initialNBDB     []libovsdbtest.TestData
		initialSBDB     []libovsdbtest.TestData
	)

	const (
		clusterIPNet   string = "10.1.0.0"
		clusterCIDR    string = clusterIPNet + "/16"
		joinSubnetCIDR string = "100.64.0.0/16/19"
		vlanID                = 1024
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		//gomega.Expect(config.PrepareTestConfig()).To(gomega.Succeed())

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags
		libovsdbCleanup = nil

		node1Chassis = sbdb.Chassis{Name: "cb9ec8fa-b409-4ef3-9f42-d9283c47aac6", Hostname: "node1", UUID: "cb9ec8fa-b409-4ef3-9f42-d9283c47aac6"}
		node2Chassis = sbdb.Chassis{Name: "cb9ec8fa-b409-4ef3-9f42-d9283c47aac7", Hostname: "node2", UUID: "cb9ec8fa-b409-4ef3-9f42-d9283c47aac7"}
		node3Chassis = sbdb.Chassis{Name: "cb9ec8fa-b409-4ef3-9f42-d9283c47aac8", Hostname: "node3", UUID: "cb9ec8fa-b409-4ef3-9f42-d9283c47aac8"}

	})

	ginkgo.AfterEach(func() {
		if libovsdbCleanup != nil {
			libovsdbCleanup.Cleanup()
		}
	})

	ginkgo.Context("Default network", func() {
		ginkgo.BeforeEach(func() {
			// node1 is a local zone node
			testNode1 = v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node1",
					Annotations: map[string]string{
						"k8s.ovn.org/node-chassis-id":                  "cb9ec8fa-b409-4ef3-9f42-d9283c47aac6",
						"k8s.ovn.org/ovn-zone":                         "global",
						"k8s.ovn.org/ovn-node-id":                      "1",
						"k8s.ovn.org/node-subnets":                     "{\"default\":[\"10.244.1.0/24\"]}",
						"k8s.ovn.org/zone-join-subnets":                "{\"default\":[\"100.44.1.0/24\"]}",
						"k8s.ovn.org/ovn-node-transit-switch-port-ips": "[\"168.254.0.1/16\"]",
						"k8s.ovn.org/ovn-gw-router-port-ips":           "[\"100.45.1.1/24\"]",
						"k8s.ovn.org/network-ids":                      "{\"default\":\"0\"}",
					},
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "10.0.0.10"}},
				},
			}
			// node2 is a local zone node
			testNode2 = v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node2",
					Annotations: map[string]string{
						"k8s.ovn.org/node-chassis-id":                  "cb9ec8fa-b409-4ef3-9f42-d9283c47aac7",
						"k8s.ovn.org/ovn-zone":                         "global",
						"k8s.ovn.org/ovn-node-id":                      "2",
						"k8s.ovn.org/node-subnets":                     "{\"default\":[\"10.244.2.0/24\"]}",
						"k8s.ovn.org/zone-join-subnets":                "{\"default\":[\"100.44.2.0/24\"]}",
						"k8s.ovn.org/ovn-node-transit-switch-port-ips": "[\"168.254.0.2/16\"]",
						"k8s.ovn.org/ovn-gw-router-port-ips":           "[\"100.45.2.1/24\"]",
						"k8s.ovn.org/network-ids":                      "{\"default\":\"0\"}",
					},
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "10.0.0.11"}},
				},
			}
			// node3 is a remote zone node
			testNode3 = v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node3",
					Annotations: map[string]string{
						"k8s.ovn.org/node-chassis-id":                  "cb9ec8fa-b409-4ef3-9f42-d9283c47aac8",
						"k8s.ovn.org/ovn-zone":                         "foo",
						"k8s.ovn.org/ovn-node-id":                      "3",
						"k8s.ovn.org/node-subnets":                     "{\"default\":[\"10.244.3.0/24\"]}",
						"k8s.ovn.org/zone-join-subnets":                "{\"default\":[\"100.44.3.0/24\"]}",
						"k8s.ovn.org/ovn-node-transit-switch-port-ips": "[\"168.254.0.3/16\"]",
						"k8s.ovn.org/ovn-gw-router-port-ips":           "[\"100.45.3.1/24\"]",
						"k8s.ovn.org/network-ids":                      "{\"default\":\"0\"}",
					},
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "10.0.0.12"}},
				},
			}
			initialNBDB = []libovsdbtest.TestData{
				newClusterJoinSwitch(),
				newOVNClusterRouter(types.DefaultNetworkName),
			}

			initialSBDB = []libovsdbtest.TestData{
				&node1Chassis, &node2Chassis, &node3Chassis}
		})

		ginkgo.It("Basic checks", func() {
			app.Action = func(ctx *cli.Context) error {
				dbSetup := libovsdbtest.TestSetup{
					NBData: initialNBDB,
					SBData: initialSBDB,
				}

				_, err := config.InitConfig(ctx, nil, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				config.Kubernetes.HostNetworkNamespace = ""

				var libovsdbOvnNBClient, libovsdbOvnSBClient libovsdbclient.Client
				libovsdbOvnNBClient, libovsdbOvnSBClient, libovsdbCleanup, err = libovsdbtest.NewNBSBTestHarness(dbSetup)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				createTransitSwitchPortBindings(libovsdbOvnSBClient, types.DefaultNetworkName, &testNode1, &testNode2, &testNode2)

				zoneICHandler := NewZoneInterconnectHandler(&util.DefaultNetInfo{}, libovsdbOvnNBClient, libovsdbOvnSBClient)
				err = invokeICHandlerAddNodeFunction("global", zoneICHandler, &testNode1, &testNode2, &testNode3)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				err = checkInterconnectResources("global", types.DefaultNetworkName, libovsdbOvnNBClient, &testNode1, &testNode2, &testNode3)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				return nil
			}

			err := app.Run([]string{
				app.Name,
				"-cluster-subnets=" + clusterCIDR,
				"-init-cluster-manager",
				"-zone-join-switch-subnets=" + joinSubnetCIDR,
				"-enable-interconnect",
			})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("Change node zones", func() {
			app.Action = func(ctx *cli.Context) error {
				dbSetup := libovsdbtest.TestSetup{
					NBData: initialNBDB,
					SBData: initialSBDB,
				}

				_, err := config.InitConfig(ctx, nil, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				config.Kubernetes.HostNetworkNamespace = ""

				var libovsdbOvnNBClient, libovsdbOvnSBClient libovsdbclient.Client
				libovsdbOvnNBClient, libovsdbOvnSBClient, libovsdbCleanup, err = libovsdbtest.NewNBSBTestHarness(dbSetup)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				createTransitSwitchPortBindings(libovsdbOvnSBClient, types.DefaultNetworkName, &testNode1, &testNode2, &testNode2)

				zoneICHandler := NewZoneInterconnectHandler(&util.DefaultNetInfo{}, libovsdbOvnNBClient, libovsdbOvnSBClient)
				err = invokeICHandlerAddNodeFunction("global", zoneICHandler, &testNode1, &testNode2, &testNode3)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				err = checkInterconnectResources("global", types.DefaultNetworkName, libovsdbOvnNBClient, &testNode1, &testNode2, &testNode3)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				// Change the zone of node2 to a remote zone
				testNode2.Annotations["k8s.ovn.org/ovn-zone"] = "bar"
				err = invokeICHandlerAddNodeFunction("global", zoneICHandler, &testNode1, &testNode2, &testNode3)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				err = checkInterconnectResources("global", types.DefaultNetworkName, libovsdbOvnNBClient, &testNode1, &testNode2, &testNode3)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				// Change the zone of node2 and node3 to global  (no remote zone nodes)
				err = invokeICHandlerAddNodeFunction("global", zoneICHandler, &testNode1, &testNode2, &testNode3)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				err = checkInterconnectResources("global", types.DefaultNetworkName, libovsdbOvnNBClient, &testNode1, &testNode2, &testNode3)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				return nil
			}

			err := app.Run([]string{
				app.Name,
				"-cluster-subnets=" + clusterCIDR,
				"-init-cluster-manager",
				"-zone-join-switch-subnets=" + joinSubnetCIDR,
				"-enable-interconnect",
			})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("Secondary networks", func() {
		ginkgo.BeforeEach(func() {
			// node1 is a local zone node
			testNode1 = v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node1",
					Annotations: map[string]string{
						"k8s.ovn.org/node-chassis-id":                  "cb9ec8fa-b409-4ef3-9f42-d9283c47aac6",
						"k8s.ovn.org/ovn-zone":                         "global",
						"k8s.ovn.org/ovn-node-id":                      "1",
						"k8s.ovn.org/node-subnets":                     "{\"blue\":[\"10.244.1.0/24\"]}",
						"k8s.ovn.org/zone-join-subnets":                "{\"blue\":[\"100.44.1.0/24\"]}",
						"k8s.ovn.org/ovn-node-transit-switch-port-ips": "[\"168.254.0.1/16\"]",
						"k8s.ovn.org/ovn-gw-router-port-ips":           "[\"100.45.1.1/24\"]",
						"k8s.ovn.org/network-ids":                      "{\"blue\":\"1\"}",
					},
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "10.0.0.10"}},
				},
			}
			// node2 is a local zone node
			testNode2 = v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node2",
					Annotations: map[string]string{
						"k8s.ovn.org/node-chassis-id":                  "cb9ec8fa-b409-4ef3-9f42-d9283c47aac7",
						"k8s.ovn.org/ovn-zone":                         "global",
						"k8s.ovn.org/ovn-node-id":                      "2",
						"k8s.ovn.org/node-subnets":                     "{\"blue\":[\"10.244.2.0/24\"]}",
						"k8s.ovn.org/zone-join-subnets":                "{\"blue\":[\"100.44.2.0/24\"]}",
						"k8s.ovn.org/ovn-node-transit-switch-port-ips": "[\"168.254.0.2/16\"]",
						"k8s.ovn.org/ovn-gw-router-port-ips":           "[\"100.45.2.1/24\"]",
						"k8s.ovn.org/network-ids":                      "{\"blue\":\"1\"}",
					},
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "10.0.0.11"}},
				},
			}
			// node3 is a remote zone node
			testNode3 = v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node3",
					Annotations: map[string]string{
						"k8s.ovn.org/node-chassis-id":                  "cb9ec8fa-b409-4ef3-9f42-d9283c47aac8",
						"k8s.ovn.org/ovn-zone":                         "foo",
						"k8s.ovn.org/ovn-node-id":                      "3",
						"k8s.ovn.org/node-subnets":                     "{\"blue\":[\"10.244.3.0/24\"]}",
						"k8s.ovn.org/zone-join-subnets":                "{\"blue\":[\"100.44.3.0/24\"]}",
						"k8s.ovn.org/ovn-node-transit-switch-port-ips": "[\"168.254.0.3/16\"]",
						"k8s.ovn.org/ovn-gw-router-port-ips":           "[\"100.45.3.1/24\"]",
						"k8s.ovn.org/network-ids":                      "{\"blue\":\"1\"}",
					},
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "10.0.0.12"}},
				},
			}
			initialNBDB = []libovsdbtest.TestData{
				newOVNClusterRouter("blue"),
			}

			initialSBDB = []libovsdbtest.TestData{
				&node1Chassis, &node2Chassis, &node3Chassis}
		})

		ginkgo.It("Basic checks", func() {
			app.Action = func(ctx *cli.Context) error {
				dbSetup := libovsdbtest.TestSetup{
					NBData: initialNBDB,
					SBData: initialSBDB,
				}

				_, err := config.InitConfig(ctx, nil, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				config.Kubernetes.HostNetworkNamespace = ""

				var libovsdbOvnNBClient, libovsdbOvnSBClient libovsdbclient.Client
				libovsdbOvnNBClient, libovsdbOvnSBClient, libovsdbCleanup, err = libovsdbtest.NewNBSBTestHarness(dbSetup)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				createTransitSwitchPortBindings(libovsdbOvnSBClient, types.DefaultNetworkName, &testNode1, &testNode2, &testNode2)

				netInfo := util.NewNetInfo(&ovncnitypes.NetConf{NetConf: cnitypes.NetConf{Name: "blue"}, Topology: types.Layer3Topology})
				zoneICHandler := NewZoneInterconnectHandler(netInfo, libovsdbOvnNBClient, libovsdbOvnSBClient)
				err = invokeICHandlerAddNodeFunction("global", zoneICHandler, &testNode1, &testNode2, &testNode3)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				err = checkInterconnectResources("global", "blue", libovsdbOvnNBClient, &testNode1, &testNode2, &testNode3)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				return nil
			}

			err := app.Run([]string{
				app.Name,
				"-cluster-subnets=" + clusterCIDR,
				"-init-cluster-manager",
				"-zone-join-switch-subnets=" + joinSubnetCIDR,
				"-enable-interconnect",
			})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("Error scenarios", func() {
		ginkgo.It("Missing annotations and error scenarios for local node", func() {
			app.Action = func(ctx *cli.Context) error {
				dbSetup := libovsdbtest.TestSetup{
					NBData: initialNBDB,
					SBData: initialSBDB,
				}

				_, err := config.InitConfig(ctx, nil, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				config.Kubernetes.HostNetworkNamespace = ""

				var libovsdbOvnNBClient, libovsdbOvnSBClient libovsdbclient.Client
				libovsdbOvnNBClient, libovsdbOvnSBClient, libovsdbCleanup, err = libovsdbtest.NewNBSBTestHarness(dbSetup)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				testNode4 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node4",
					},
					Status: v1.NodeStatus{
						Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "10.0.0.10"}},
					},
				}

				createTransitSwitchPortBindings(libovsdbOvnSBClient, types.DefaultNetworkName, &testNode1, &testNode2, &testNode2)

				zoneICHandler := NewZoneInterconnectHandler(&util.DefaultNetInfo{}, libovsdbOvnNBClient, libovsdbOvnSBClient)
				gomega.Expect(zoneICHandler).NotTo(gomega.BeNil())

				err = zoneICHandler.AddLocalZoneNode(&testNode4)
				gomega.Expect(err).To(gomega.HaveOccurred(), "failed to get node id for node - node4")

				// Set the node id
				testNode4.Annotations = map[string]string{"k8s.ovn.org/ovn-node-id": "4"}
				err = zoneICHandler.AddLocalZoneNode(&testNode4)
				gomega.Expect(err).To(gomega.HaveOccurred(), "failed to get the node transit switch port ips for node node4")

				// Set the node transit switch port ips
				testNode4.Annotations["k8s.ovn.org/ovn-node-transit-switch-port-ips"] = "[\"168.254.0.4/16\"]"
				err = zoneICHandler.AddLocalZoneNode(&testNode4)
				gomega.Expect(err).To(gomega.HaveOccurred(), "failed to get the network id for the network default on node node4")

				// Set the network id for default network
				testNode4.Annotations["k8s.ovn.org/network-ids"] = "{\"default\":\"0\"}"
				err = zoneICHandler.AddLocalZoneNode(&testNode4)
				gomega.Expect(err).To(gomega.HaveOccurred(), "failed to create/update cluster router ovn_cluster_router to add transit switch port rtots-node4 for the node node4")

				// Create the cluster router
				r := newOVNClusterRouter(types.DefaultNetworkName)
				err = libovsdbops.CreateOrUpdateLogicalRouter(libovsdbOvnNBClient, r)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				err = zoneICHandler.AddLocalZoneNode(&testNode4)
				gomega.Expect(err).To(gomega.HaveOccurred(), "failed to parse node node4 subnets annotation")

				// Set node subnet annotation
				testNode4.Annotations["k8s.ovn.org/node-subnets"] = "{\"default\":[\"10.244.4.0/24\"]}"

				err = zoneICHandler.AddLocalZoneNode(&testNode4)
				gomega.Expect(err).To(gomega.HaveOccurred(), "failed to parse node node4 join subnets annotation")

				// Set node join subnet annotation
				testNode4.Annotations["k8s.ovn.org/zone-join-subnets"] = "{\"default\":[\"100.44.4.0/24\"]}"
				err = zoneICHandler.AddLocalZoneNode(&testNode4)
				gomega.Expect(err).To(gomega.HaveOccurred(), "failed to parse node node4 GR IPs annotation")

				// Set node ovn-gw-router-port-ips annotation
				testNode4.Annotations["k8s.ovn.org/ovn-gw-router-port-ips"] = "[\"100.45.4.1/24\"]"
				err = zoneICHandler.AddLocalZoneNode(&testNode4)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				err = checkInterconnectResources("global", types.DefaultNetworkName, libovsdbOvnNBClient, &testNode4)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				return nil
			}

			err := app.Run([]string{
				app.Name,
				"-cluster-subnets=" + clusterCIDR,
				"-init-cluster-manager",
				"-zone-join-switch-subnets=" + joinSubnetCIDR,
				"-enable-interconnect",
			})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("Missing annotations and error scenarios for remote node", func() {
			app.Action = func(ctx *cli.Context) error {
				dbSetup := libovsdbtest.TestSetup{
					NBData: initialNBDB,
					SBData: initialSBDB,
				}

				_, err := config.InitConfig(ctx, nil, nil)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				config.Kubernetes.HostNetworkNamespace = ""

				var libovsdbOvnNBClient, libovsdbOvnSBClient libovsdbclient.Client
				libovsdbOvnNBClient, libovsdbOvnSBClient, libovsdbCleanup, err = libovsdbtest.NewNBSBTestHarness(dbSetup)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				testNode4 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node4",
						Annotations: map[string]string{
							"k8s.ovn.org/ovn-zone": "foo",
						},
					},
					Status: v1.NodeStatus{
						Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "10.0.0.10"}},
					},
				}

				createTransitSwitchPortBindings(libovsdbOvnSBClient, types.DefaultNetworkName, &testNode1, &testNode2, &testNode2)

				zoneICHandler := NewZoneInterconnectHandler(&util.DefaultNetInfo{}, libovsdbOvnNBClient, libovsdbOvnSBClient)
				gomega.Expect(zoneICHandler).NotTo(gomega.BeNil())

				err = zoneICHandler.AddRemoteZoneNode(&testNode4)
				gomega.Expect(err).To(gomega.HaveOccurred(), "failed to get node id for node - node4")

				// Set the node id
				testNode4.Annotations["k8s.ovn.org/ovn-node-id"] = "4"
				err = zoneICHandler.AddRemoteZoneNode(&testNode4)
				gomega.Expect(err).To(gomega.HaveOccurred(), "failed to parse node chassis-id for node")

				// Set the node-chassis-id
				testNode4.Annotations["k8s.ovn.org/node-chassis-id"] = "cb9ec8fa-b409-4ef3-9f42-d9283c47aac9"
				err = zoneICHandler.AddRemoteZoneNode(&testNode4)
				gomega.Expect(err).To(gomega.HaveOccurred(), "failed to get the node transit switch port ips for node node4")

				// Set the node transit switch port ips
				testNode4.Annotations["k8s.ovn.org/ovn-node-transit-switch-port-ips"] = "[\"168.254.0.4/16\"]"
				err = zoneICHandler.AddRemoteZoneNode(&testNode4)
				gomega.Expect(err).To(gomega.HaveOccurred(), "failed to get the network id for the network default on node node4")

				// Set the network id for default network
				testNode4.Annotations["k8s.ovn.org/network-ids"] = "{\"default\":\"0\"}"
				err = zoneICHandler.AddLocalZoneNode(&testNode4)
				gomega.Expect(err).To(gomega.HaveOccurred(), "failed to update chassis node4 for remote port tstor-node4")

				// Create remote chassis
				err = libovsdbops.CreateOrUpdateRemoteChassis(libovsdbOvnSBClient, "node4", "cb9ec8fa-b409-4ef3-9f42-d9283c47aac9", "10.0.0.4")
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				err = zoneICHandler.AddRemoteZoneNode(&testNode4)
				gomega.Expect(err).To(gomega.HaveOccurred(), "failed to parse node node4 subnets annotation")

				// Set node subnet annotation
				testNode4.Annotations["k8s.ovn.org/node-subnets"] = "{\"default\":[\"10.244.4.0/24\"]}"
				err = zoneICHandler.AddRemoteZoneNode(&testNode4)
				gomega.Expect(err).To(gomega.HaveOccurred(), "unable to create static routes")

				// Create the cluster router
				r := newOVNClusterRouter(types.DefaultNetworkName)
				err = libovsdbops.CreateOrUpdateLogicalRouter(libovsdbOvnNBClient, r)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				err = zoneICHandler.AddRemoteZoneNode(&testNode4)
				gomega.Expect(err).To(gomega.HaveOccurred(), "failed to parse node node4 join subnets annotation")

				// Set node join subnet annotation
				testNode4.Annotations["k8s.ovn.org/zone-join-subnets"] = "{\"default\":[\"100.44.4.0/24\"]}"
				err = zoneICHandler.AddRemoteZoneNode(&testNode4)
				gomega.Expect(err).To(gomega.HaveOccurred(), "failed to parse node node4 GR IPs annotation")

				// Set node ovn-gw-router-port-ips annotation
				testNode4.Annotations["k8s.ovn.org/ovn-gw-router-port-ips"] = "[\"100.45.4.1/24\"]"
				err = zoneICHandler.AddRemoteZoneNode(&testNode4)

				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				err = checkInterconnectResources("global", types.DefaultNetworkName, libovsdbOvnNBClient, &testNode4)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				return nil
			}

			err := app.Run([]string{
				app.Name,
				"-cluster-subnets=" + clusterCIDR,
				"-init-cluster-manager",
				"-zone-join-switch-subnets=" + joinSubnetCIDR,
				"-enable-interconnect",
			})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

	})
})
