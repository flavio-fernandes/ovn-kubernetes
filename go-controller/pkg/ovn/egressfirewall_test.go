package ovn

import (
	"context"
	"encoding/json"
	"fmt"

	"net"
	"time"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/urfave/cli/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressfirewallapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	lsm "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/logical_switch_manager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/retry"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/sbdb"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	t "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
)

func newObjectMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		UID:       types.UID(namespace),
		Name:      name,
		Namespace: namespace,
	}

}

func newEgressFirewallObject(name, namespace string, egressRules []egressfirewallapi.EgressFirewallRule) *egressfirewallapi.EgressFirewall {

	return &egressfirewallapi.EgressFirewall{
		ObjectMeta: newObjectMeta(name, namespace),
		Spec: egressfirewallapi.EgressFirewallSpec{
			Egress: egressRules,
		},
	}
}

var _ = ginkgo.Describe("OVN EgressFirewall Operations", func() {
	var (
		app                    *cli.App
		fakeOVN                *FakeOVN
		clusterPortGroup       *nbdb.PortGroup
		nodeSwitch, joinSwitch *nbdb.LogicalSwitch
		initialData            []libovsdbtest.TestData
		dbSetup                libovsdbtest.TestSetup
	)
	const (
		node1Name string = "node1"
		node2Name string = "node2"
	)

	clusterRouter := &nbdb.LogicalRouter{
		UUID: t.OVNClusterRouter + "-UUID",
		Name: t.OVNClusterRouter,
	}

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()
		config.OVNKubernetesFeature.EnableEgressFirewall = true

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fakeOVN = NewFakeOVN()
		clusterPortGroup = newClusterPortGroup()
		nodeSwitch = &nbdb.LogicalSwitch{
			UUID: node1Name + "-UUID",
			Name: node1Name,
		}
		joinSwitch = &nbdb.LogicalSwitch{
			UUID: "join-UUID",
			Name: "join",
		}
		initialData = []libovsdbtest.TestData{
			nodeSwitch,
			joinSwitch,
			clusterPortGroup,
			clusterRouter,
		}
		dbSetup = libovsdbtest.TestSetup{
			NBData: initialData,
		}
	})

	ginkgo.AfterEach(func() {
		fakeOVN.shutdown()
	})

	ginkgo.Context("on startup", func() {
		for _, gwMode := range []config.GatewayMode{config.GatewayModeLocal, config.GatewayModeShared} {
			config.Gateway.Mode = gwMode
			ginkgo.It(fmt.Sprintf("reconciles stale ACLs, gateway mode %s", gwMode), func() {
				app.Action = func(ctx *cli.Context) error {
					purgeACL := libovsdbops.BuildACL(
						buildEgressFwAclName("namespace1", t.EgressFirewallStartPriority),
						nbdb.ACLDirectionFromLport,
						t.EgressFirewallStartPriority,
						"",
						nbdb.ACLActionDrop,
						t.OvnACLLoggingMeter,
						"",
						false,
						map[string]string{egressFirewallACLExtIdKey: "none"},
						nil,
					)
					purgeACL.UUID = "purgeACL-UUID"

					namespace1 := *newNamespace("namespace1")
					egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
						{
							Type: "Allow",
							To: egressfirewallapi.EgressFirewallDestination{
								CIDRSelector: "1.2.3.4/23",
							},
						},
					})
					keepACL := libovsdbops.BuildACL(
						"",
						nbdb.ACLDirectionFromLport,
						t.EgressFirewallStartPriority,
						"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && ip4.dst != 10.128.0.0/14",
						nbdb.ACLActionAllow,
						t.OvnACLLoggingMeter,
						nbdb.ACLSeverityInfo,
						false,
						map[string]string{egressFirewallACLExtIdKey: namespace1.Name},
						nil,
					)
					keepACL.UUID = "keepACL-UUID"

					// this ACL is not in the egress firewall priority range and should be untouched
					otherACL := libovsdbops.BuildACL(
						buildEgressFwAclName("namespace1", t.EgressFirewallStartPriority-1),
						nbdb.ACLDirectionFromLport,
						t.MinimumReservedEgressFirewallPriority-1,
						"",
						nbdb.ACLActionDrop,
						t.OvnACLLoggingMeter,
						"",
						false,
						map[string]string{egressFirewallACLExtIdKey: "default"},
						nil,
					)
					otherACL.UUID = "otherACL-UUID"

					nodeSwitch.ACLs = []string{purgeACL.UUID, keepACL.UUID}
					joinSwitch.ACLs = []string{purgeACL.UUID, keepACL.UUID}

					dbSetup := libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							otherACL,
							purgeACL,
							keepACL,
							nodeSwitch,
							joinSwitch,
							clusterRouter,
							clusterPortGroup,
						},
					}

					fakeOVN.startWithDBSetup(dbSetup,
						&v1.NodeList{
							Items: []v1.Node{
								{
									Status: v1.NodeStatus{
										Phase: v1.NodeRunning,
									},
									ObjectMeta: newObjectMeta(node1Name, ""),
								},
							},
						})

					// only create one egressFirewall
					_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(namespace1.Name).
						Create(context.TODO(), egressFirewall, metav1.CreateOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					err = fakeOVN.controller.WatchEgressFirewall()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					// Both ACLs will be removed from the join switch
					joinSwitch.ACLs = nil
					// Both ACLs will be removed from the node switch
					nodeSwitch.ACLs = nil

					// keepACL will be added to the clusterPortGroup
					clusterPortGroup.ACLs = []string{keepACL.UUID}

					// Direction of both ACLs will be converted to
					keepACL.Direction = nbdb.ACLDirectionToLport
					newName := buildEgressFwAclName(namespace1.Name, t.EgressFirewallStartPriority)
					keepACL.Name = &newName
					// check severity was reset from default to nil
					keepACL.Severity = nil
					// subnet exclusion will be deleted
					asHash, _ := getNsAddrSetHashNames(namespace1.Name)
					keepACL.Match = "(ip4.dst == 1.2.3.4/23) && ip4.src == $" + asHash

					// purgeACL ACL will be deleted when test server starts deleting dereferenced ACLs
					// for now we need to update its fields, since it is present in the db
					purgeACL.Direction = nbdb.ACLDirectionToLport
					newName2 := buildEgressFwAclName("none", t.EgressFirewallStartPriority)
					purgeACL.Name = &newName2
					purgeACL.Severity = nil

					expectedDatabaseState := []libovsdb.TestData{
						otherACL,
						purgeACL,
						keepACL,
						nodeSwitch,
						joinSwitch,
						clusterRouter,
						clusterPortGroup,
					}

					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
					return nil
				}

				err := app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

			})
			ginkgo.It(fmt.Sprintf("reconciles an existing egressFirewall with IPv4 CIDR, gateway mode %s", gwMode), func() {
				app.Action = func(ctx *cli.Context) error {
					namespace1 := *newNamespace("namespace1")
					egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
						{
							Type: "Allow",
							To: egressfirewallapi.EgressFirewallDestination{
								CIDRSelector: "1.2.3.4/23",
							},
						},
					})

					fakeOVN.startWithDBSetup(dbSetup,
						&egressfirewallapi.EgressFirewallList{
							Items: []egressfirewallapi.EgressFirewall{
								*egressFirewall,
							},
						},
						&v1.NamespaceList{
							Items: []v1.Namespace{
								namespace1,
							},
						}, &v1.NodeList{
							Items: []v1.Node{
								{
									Status: v1.NodeStatus{
										Phase: v1.NodeRunning,
									},
									ObjectMeta: newObjectMeta(node1Name, ""),
								},
							},
						})

					err := fakeOVN.controller.WatchNamespaces()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					err = fakeOVN.controller.WatchEgressFirewall()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					_, err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					asHash, _ := getNsAddrSetHashNames(namespace1.Name)
					ipv4ACL := libovsdbops.BuildACL(
						buildEgressFwAclName("namespace1", t.EgressFirewallStartPriority),
						nbdb.ACLDirectionToLport,
						t.EgressFirewallStartPriority,
						"(ip4.dst == 1.2.3.4/23) && ip4.src == $"+asHash,
						nbdb.ACLActionAllow,
						t.OvnACLLoggingMeter,
						"",
						false,
						map[string]string{egressFirewallACLExtIdKey: "namespace1"},
						nil,
					)
					ipv4ACL.UUID = "ipv4ACL-UUID"

					// new ACL will be added to the port group
					clusterPortGroup.ACLs = []string{ipv4ACL.UUID}
					expectedDatabaseState := append(initialData, ipv4ACL)
					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

					return nil
				}

				err := app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

			})
			ginkgo.It(fmt.Sprintf("reconciles an existing egressFirewall with IPv6 CIDR, gateway mode %s", gwMode), func() {
				app.Action = func(ctx *cli.Context) error {
					namespace1 := *newNamespace("namespace1")
					egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
						{
							Type: "Allow",
							To: egressfirewallapi.EgressFirewallDestination{
								CIDRSelector: "2002::1234:abcd:ffff:c0a8:101/64",
							},
						},
					})

					fakeOVN.startWithDBSetup(dbSetup,
						&egressfirewallapi.EgressFirewallList{
							Items: []egressfirewallapi.EgressFirewall{
								*egressFirewall,
							},
						},
						&v1.NamespaceList{
							Items: []v1.Namespace{
								namespace1,
							},
						}, &v1.NodeList{
							Items: []v1.Node{
								{
									Status: v1.NodeStatus{
										Phase: v1.NodeRunning,
									},
									ObjectMeta: newObjectMeta(node1Name, ""),
								},
							},
						})
					config.IPv6Mode = true

					err := fakeOVN.controller.WatchNamespaces()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					err = fakeOVN.controller.WatchEgressFirewall()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					_, err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					_, asHash6 := getNsAddrSetHashNames(namespace1.Name)
					ipv6ACL := libovsdbops.BuildACL(
						buildEgressFwAclName("namespace1", t.EgressFirewallStartPriority),
						nbdb.ACLDirectionToLport,
						t.EgressFirewallStartPriority,
						"(ip6.dst == 2002::1234:abcd:ffff:c0a8:101/64) && ip6.src == $"+asHash6,
						nbdb.ACLActionAllow,
						t.OvnACLLoggingMeter,
						"",
						false,
						map[string]string{egressFirewallACLExtIdKey: "namespace1"},
						nil,
					)
					ipv6ACL.UUID = "ipv6ACL-UUID"

					// new ACL will be added to the port group
					clusterPortGroup.ACLs = []string{ipv6ACL.UUID}
					expectedDatabaseState := append(initialData, ipv6ACL)
					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

					return nil
				}

				err := app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

			})
		}
	})
	ginkgo.Context("during execution", func() {
		for _, gwMode := range []config.GatewayMode{config.GatewayModeLocal, config.GatewayModeShared} {
			config.Gateway.Mode = gwMode
			ginkgo.It(fmt.Sprintf("correctly creates an egressfirewall denying traffic udp traffic on port 100, gateway mode %s", gwMode), func() {
				app.Action = func(ctx *cli.Context) error {
					namespace1 := *newNamespace("namespace1")
					egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
						{
							Type: "Deny",
							Ports: []egressfirewallapi.EgressFirewallPort{
								{
									Protocol: "UDP",
									Port:     100,
								},
							},
							To: egressfirewallapi.EgressFirewallDestination{
								CIDRSelector: "1.2.3.4/23",
							},
						},
					})
					fakeOVN.startWithDBSetup(dbSetup,
						&egressfirewallapi.EgressFirewallList{
							Items: []egressfirewallapi.EgressFirewall{
								*egressFirewall,
							},
						},
						&v1.NamespaceList{
							Items: []v1.Namespace{
								namespace1,
							},
						},
						&v1.NodeList{
							Items: []v1.Node{
								{
									Status: v1.NodeStatus{
										Phase: v1.NodeRunning,
									},
									ObjectMeta: newObjectMeta(node1Name, ""),
								},
							},
						})

					err := fakeOVN.controller.WatchNamespaces()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					_, err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					fakeOVN.controller.WatchEgressFirewall()
					asHash, _ := getNsAddrSetHashNames(namespace1.Name)
					udpACL := libovsdbops.BuildACL(
						buildEgressFwAclName("namespace1", t.EgressFirewallStartPriority),
						nbdb.ACLDirectionToLport,
						t.EgressFirewallStartPriority,
						"(ip4.dst == 1.2.3.4/23) && ip4.src == $"+asHash+" && ((udp && ( udp.dst == 100 )))",
						nbdb.ACLActionDrop,
						t.OvnACLLoggingMeter,
						"",
						false,
						map[string]string{egressFirewallACLExtIdKey: "namespace1"},
						nil,
					)
					udpACL.UUID = "udpACL-UUID"

					// new ACL will be added to the port group
					clusterPortGroup.ACLs = []string{udpACL.UUID}
					expectedDatabaseState := append(initialData, udpACL)
					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

					return nil
				}
				err := app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			})
			ginkgo.It(fmt.Sprintf("correctly deletes an egressfirewall, gateway mode %s", gwMode), func() {
				app.Action = func(ctx *cli.Context) error {
					namespace1 := *newNamespace("namespace1")
					egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
						{
							Type: "Allow",
							Ports: []egressfirewallapi.EgressFirewallPort{
								{
									Protocol: "TCP",
									Port:     100,
								},
							},
							To: egressfirewallapi.EgressFirewallDestination{
								CIDRSelector: "1.2.3.5/23",
							},
						},
					})

					fakeOVN.startWithDBSetup(dbSetup,
						&egressfirewallapi.EgressFirewallList{
							Items: []egressfirewallapi.EgressFirewall{
								*egressFirewall,
							},
						},
						&v1.NamespaceList{
							Items: []v1.Namespace{
								namespace1,
							},
						}, &v1.NodeList{
							Items: []v1.Node{
								{
									Status: v1.NodeStatus{
										Phase: v1.NodeRunning,
									},
									ObjectMeta: newObjectMeta(node1Name, ""),
								},
								{
									Status: v1.NodeStatus{
										Phase: v1.NodeRunning,
									},
									ObjectMeta: newObjectMeta(node2Name, ""),
								},
							},
						})

					err := fakeOVN.controller.WatchNamespaces()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					err = fakeOVN.controller.WatchEgressFirewall()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					asHash, _ := getNsAddrSetHashNames(namespace1.Name)
					ipv4ACL := libovsdbops.BuildACL(
						buildEgressFwAclName("namespace1", t.EgressFirewallStartPriority),
						nbdb.ACLDirectionToLport,
						t.EgressFirewallStartPriority,
						"(ip4.dst == 1.2.3.5/23) && ip4.src == $"+asHash+" && ((tcp && ( tcp.dst == 100 )))",
						nbdb.ACLActionAllow,
						t.OvnACLLoggingMeter,
						"",
						false,
						map[string]string{egressFirewallACLExtIdKey: "namespace1"},
						nil,
					)
					ipv4ACL.UUID = "ipv4ACL-UUID"

					// new ACL will be added to the port group
					clusterPortGroup.ACLs = []string{ipv4ACL.UUID}
					expectedDatabaseState := append(initialData, ipv4ACL)

					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

					err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Delete(context.TODO(), egressFirewall.Name, *metav1.NewDeleteOptions(0))
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					// ACL should be removed from the port group egfw is deleted
					clusterPortGroup.ACLs = []string{}
					// this ACL will be deleted when test server starts deleting dereferenced ACLs
					expectedDatabaseState = append(initialData, ipv4ACL)
					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

					return nil
				}

				err := app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			})
			ginkgo.It(fmt.Sprintf("correctly updates an egressfirewall, gateway mode %s", gwMode), func() {
				app.Action = func(ctx *cli.Context) error {
					namespace1 := *newNamespace("namespace1")
					egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
						{
							Type: "Allow",
							To: egressfirewallapi.EgressFirewallDestination{
								CIDRSelector: "1.2.3.4/23",
							},
						},
					})
					egressFirewall1 := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
						{
							Type: "Deny",
							To: egressfirewallapi.EgressFirewallDestination{
								CIDRSelector: "1.2.3.4/23",
							},
						},
					})

					fakeOVN.startWithDBSetup(dbSetup,
						&egressfirewallapi.EgressFirewallList{
							Items: []egressfirewallapi.EgressFirewall{
								*egressFirewall,
							},
						},
						&v1.NamespaceList{
							Items: []v1.Namespace{
								namespace1,
							},
						},
						&v1.NodeList{
							Items: []v1.Node{
								{
									Status: v1.NodeStatus{
										Phase: v1.NodeRunning,
									},
									ObjectMeta: newObjectMeta(node1Name, ""),
								},
							},
						})

					err := fakeOVN.controller.WatchNamespaces()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					err = fakeOVN.controller.WatchEgressFirewall()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					asHash, _ := getNsAddrSetHashNames(namespace1.Name)
					ipv4ACL := libovsdbops.BuildACL(
						buildEgressFwAclName("namespace1", t.EgressFirewallStartPriority),
						nbdb.ACLDirectionToLport,
						t.EgressFirewallStartPriority,
						"(ip4.dst == 1.2.3.4/23) && ip4.src == $"+asHash,
						nbdb.ACLActionAllow,
						t.OvnACLLoggingMeter,
						"",
						false,
						map[string]string{egressFirewallACLExtIdKey: "namespace1"},
						nil,
					)
					ipv4ACL.UUID = "ipv4ACL-UUID"

					// new ACL will be added to the port group
					clusterPortGroup.ACLs = []string{ipv4ACL.UUID}
					expectedDatabaseState := append(initialData, ipv4ACL)
					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

					_, err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					_, err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall1.Namespace).Update(context.TODO(), egressFirewall1, metav1.UpdateOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					ipv4ACL.Action = nbdb.ACLActionDrop
					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

					return nil
				}

				err := app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

			})
			ginkgo.It(fmt.Sprintf("egress firewall with node selector updates during node update, gateway mode %s", gwMode), func() {
				config.Gateway.Mode = gwMode
				config.Gateway.NodeportEnable = true
				const (
					clusterIPNet string = "10.1.0.0"
					clusterCIDR  string = clusterIPNet + "/16"
				)
				var err error
				config.Default.ClusterSubnets, err = config.ParseClusterSubnetEntries(clusterCIDR)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				node1 := tNode{
					Name:                 "node1",
					NodeIP:               "9.9.9.9",
					NodeLRPMAC:           "0a:58:0a:01:01:01",
					LrpIP:                "100.64.0.2",
					LrpIPv6:              "fd98::2",
					DrLrpIP:              "100.64.0.1",
					PhysicalBridgeMAC:    "11:22:33:44:55:66",
					SystemID:             "cb9ec8fa-b409-4ef3-9f42-d9283c47aac6",
					NodeSubnet:           "10.1.1.0/24",
					GWRouter:             t.GWRouterPrefix + "node1",
					GatewayRouterIPMask:  "172.16.16.2/24",
					GatewayRouterIP:      "172.16.16.2",
					GatewayRouterNextHop: "172.16.16.1",
					PhysicalBridgeName:   "br-eth0",
					NodeGWIP:             "10.1.1.1/24",
					NodeMgmtPortIP:       "10.1.1.2",
					NodeMgmtPortMAC:      "0a:58:0a:01:01:02",
					DnatSnatIP:           "169.254.0.1",
				}

				app.Action = func(ctx *cli.Context) error {
					expectedOVNClusterRouter := newOVNClusterRouter()
					expectedNodeSwitch := &nbdb.LogicalSwitch{
						UUID: node1.Name + "-UUID",
						Name: node1.Name,
					}
					expectedClusterRouterPortGroup := newRouterPortGroup()
					expectedClusterPortGroup := newClusterPortGroup()
					expectedClusterLBGroup := newLoadBalancerGroup(t.ClusterLBGroupName)
					expectedSwitchLBGroup := newLoadBalancerGroup(t.ClusterSwitchLBGroupName)
					expectedRouterLBGroup := newLoadBalancerGroup(t.ClusterRouterLBGroupName)
					joinSwitch := newClusterJoinSwitch()

					initialTestData := []libovsdbtest.TestData{
						joinSwitch,
						expectedOVNClusterRouter,
						expectedNodeSwitch,
						expectedClusterRouterPortGroup,
						expectedClusterPortGroup,
						expectedClusterLBGroup,
						expectedSwitchLBGroup,
						expectedRouterLBGroup,
					}
					gr := t.GWRouterPrefix + node1.Name
					datapath := &sbdb.DatapathBinding{
						UUID:        gr + "-UUID",
						ExternalIDs: map[string]string{"logical-router": gr + "-UUID", "name": gr},
					}
					dbSetup := libovsdbtest.TestSetup{
						NBData: initialTestData,
						SBData: []libovsdbtest.TestData{datapath},
					}

					labelKey := "name"
					labelValue := "test"
					selector := metav1.LabelSelector{MatchLabels: map[string]string{labelKey: labelValue}}
					namespace1 := *newNamespace("namespace1")
					egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
						{
							Type: "Allow",
							To: egressfirewallapi.EgressFirewallDestination{
								NodeSelector: selector,
							},
						},
					})

					mdata := newObjectMeta(node1.Name, "")
					fakeOVN.startWithDBSetup(dbSetup,
						&egressfirewallapi.EgressFirewallList{
							Items: []egressfirewallapi.EgressFirewall{
								*egressFirewall,
							},
						},
						&v1.NamespaceList{
							Items: []v1.Namespace{
								namespace1,
							},
						},
						&v1.NodeList{
							Items: []v1.Node{
								{
									Status: v1.NodeStatus{
										Phase:     v1.NodeRunning,
										Addresses: []v1.NodeAddress{{v1.NodeInternalIP, node1.NodeIP}},
									},
									ObjectMeta: mdata,
								},
							},
						})

					fakeOVN.controller.multicastSupport = false
					fakeOVN.controller.SCTPSupport = true

					fakeOVN.controller.defaultCOPPUUID, err = EnsureDefaultCOPP(fakeOVN.nbClient)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					_, clusterNetwork, err := net.ParseCIDR(clusterCIDR)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					netEntry := config.CIDRNetworkEntry{CIDR: clusterNetwork, HostSubnetLength: 24}
					fakeOVN.controller.masterSubnetAllocator.InitRanges([]config.CIDRNetworkEntry{netEntry})

					// Add subnet to otherconfig for node
					expectedNodeSwitch.OtherConfig = map[string]string{"subnet": node1.NodeSubnet}

					// Add cluster LB Group to node switch.
					expectedNodeSwitch.LoadBalancerGroup = []string{expectedClusterLBGroup.UUID, expectedSwitchLBGroup.UUID}

					expectedDatabaseState := []libovsdb.TestData{}
					expectedDatabaseState = addNodeLogicalFlows(expectedDatabaseState, expectedOVNClusterRouter, expectedNodeSwitch, expectedClusterRouterPortGroup, expectedClusterPortGroup, &node1)

					ifaceID := node1.PhysicalBridgeName + "_" + node1.Name
					vlanID := uint(1024)
					l3Config := &util.L3GatewayConfig{
						Mode:           config.GatewayModeShared,
						ChassisID:      node1.SystemID,
						InterfaceID:    ifaceID,
						MACAddress:     ovntest.MustParseMAC(node1.PhysicalBridgeMAC),
						IPAddresses:    ovntest.MustParseIPNets(node1.GatewayRouterIPMask),
						NextHops:       ovntest.MustParseIPs(node1.GatewayRouterNextHop),
						NodePortEnable: true,
						VLANID:         &vlanID,
					}
					nodeAnnotator := kube.NewNodeAnnotator(&kube.Kube{fakeOVN.fakeClient.KubeClient}, node1.Name)

					err = util.SetL3GatewayConfig(nodeAnnotator, l3Config)
					err = util.SetNodeManagementPortMACAddress(nodeAnnotator, ovntest.MustParseMAC(node1.NodeMgmtPortMAC))
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					err = util.SetNodeHostSubnetAnnotation(nodeAnnotator, ovntest.MustParseIPNets(node1.NodeSubnet))
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					err = util.SetNodeHostAddresses(nodeAnnotator, sets.NewString(node1.NodeIP))
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					err = nodeAnnotator.Run()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					fakeOVN.controller.joinSwIPManager, _ = lsm.NewJoinLogicalSwitchIPManager(fakeOVN.nbClient, expectedNodeSwitch.UUID, []string{nodeName})
					_, err = fakeOVN.controller.joinSwIPManager.EnsureJoinLRPIPs(t.OVNClusterRouter)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gwLRPIPs, err := fakeOVN.controller.joinSwIPManager.EnsureJoinLRPIPs(node1.Name)
					gomega.Expect(len(gwLRPIPs) != 0).To(gomega.BeTrue())

					nodeSubnet := ovntest.MustParseIPNet(node1.NodeSubnet)
					var clusterSubnets []*net.IPNet
					for _, clusterSubnet := range config.Default.ClusterSubnets {
						clusterSubnets = append(clusterSubnets, clusterSubnet.CIDR)
					}
					joinLRPIP, joinLRNetwork, _ := net.ParseCIDR(node1.LrpIP + "/16")
					dLRPIP, dLRPNetwork, _ := net.ParseCIDR(node1.DrLrpIP + "/16")

					joinLRPIPs := &net.IPNet{
						IP:   joinLRPIP,
						Mask: joinLRNetwork.Mask,
					}
					dLRPIPs := &net.IPNet{
						IP:   dLRPIP,
						Mask: dLRPNetwork.Mask,
					}

					skipSnat := false
					expectedDatabaseState = generateGatewayInitExpectedNB(expectedDatabaseState, expectedOVNClusterRouter,
						expectedNodeSwitch, node1.Name, clusterSubnets, []*net.IPNet{nodeSubnet}, l3Config,
						[]*net.IPNet{joinLRPIPs}, []*net.IPNet{dLRPIPs}, skipSnat, node1.NodeMgmtPortIP, "1400")

					ginkgo.By("Startup with node add that wont match Egress Firewall nodeSelector")
					err = fakeOVN.controller.WatchNamespaces()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					err = fakeOVN.controller.WatchNodes()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					err = fakeOVN.controller.WatchEgressFirewall()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					err = fakeOVN.controller.WatchEgressFwNodes()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

					// update the node to match the selector
					patch := struct {
						Metadata map[string]interface{} `json:"metadata"`
					}{
						Metadata: map[string]interface{}{
							"labels": map[string]string{labelKey: labelValue},
						},
					}
					ginkgo.By("Updating a node to match nodeSelector on Egress Firewall")
					patchData, err := json.Marshal(&patch)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					// trigger update event
					_, err = fakeOVN.fakeClient.KubeClient.CoreV1().Nodes().Patch(context.TODO(), node1.Name, types.MergePatchType, patchData, metav1.PatchOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					asHash, _ := getNsAddrSetHashNames(namespace1.Name)
					ipv4ACL := libovsdbops.BuildACL(
						buildEgressFwAclName("namespace1", t.EgressFirewallStartPriority),
						nbdb.ACLDirectionToLport,
						t.EgressFirewallStartPriority,
						fmt.Sprintf("(ip4.dst == %s) && ip4.src == $%s", node1.NodeIP, asHash),
						nbdb.ACLActionAllow,
						t.OvnACLLoggingMeter,
						"",
						false,
						map[string]string{"egressFirewall": "namespace1"},
						nil,
					)
					ipv4ACL.UUID = "ipv4ACL-UUID"

					// new ACL will be added to the port group
					expectedClusterPortGroup.ACLs = []string{ipv4ACL.UUID}
					expectedDatabaseState = append(expectedDatabaseState, ipv4ACL)
					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

					ginkgo.By("Updating a node to not match nodeSelector on Egress Firewall")
					patch.Metadata = map[string]interface{}{"labels": map[string]string{labelKey: noneMatch}}
					patchData, err = json.Marshal(&patch)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					// trigger update event
					_, err = fakeOVN.fakeClient.KubeClient.CoreV1().Nodes().Patch(context.TODO(), node1.Name, types.MergePatchType, patchData, metav1.PatchOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					expectedClusterPortGroup.ACLs = []string{}
					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

					return nil
				}

				err = app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			})
			ginkgo.It(fmt.Sprintf("correctly retries deleting an egressfirewall, gateway mode %s", gwMode), func() {
				app.Action = func(ctx *cli.Context) error {
					namespace1 := *newNamespace("namespace1")
					egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
						{
							Type: "Allow",
							Ports: []egressfirewallapi.EgressFirewallPort{
								{
									Protocol: "TCP",
									Port:     100,
								},
							},
							To: egressfirewallapi.EgressFirewallDestination{
								CIDRSelector: "1.2.3.5/23",
							},
						},
					})

					fakeOVN.startWithDBSetup(dbSetup,
						&egressfirewallapi.EgressFirewallList{
							Items: []egressfirewallapi.EgressFirewall{
								*egressFirewall,
							},
						},
						&v1.NodeList{
							Items: []v1.Node{
								{
									Status: v1.NodeStatus{
										Phase: v1.NodeRunning,
									},
									ObjectMeta: newObjectMeta(node1Name, ""),
								},
								{
									Status: v1.NodeStatus{
										Phase: v1.NodeRunning,
									},
									ObjectMeta: newObjectMeta(node2Name, ""),
								},
							},
						})

					fakeOVN.controller.WatchEgressFirewall()

					asHash, _ := getNsAddrSetHashNames(namespace1.Name)
					ipv4ACL := libovsdbops.BuildACL(
						buildEgressFwAclName("namespace1", t.EgressFirewallStartPriority),
						nbdb.ACLDirectionToLport,
						t.EgressFirewallStartPriority,
						"(ip4.dst == 1.2.3.5/23) && ip4.src == $"+asHash+" && ((tcp && ( tcp.dst == 100 )))",
						nbdb.ACLActionAllow,
						t.OvnACLLoggingMeter,
						"",
						false,
						map[string]string{egressFirewallACLExtIdKey: "namespace1"},
						nil,
					)
					ipv4ACL.UUID = "ipv4ACL-UUID"

					// new ACL will be added to the port group
					clusterPortGroup.ACLs = []string{ipv4ACL.UUID}
					expectedDatabaseState := append(initialData, ipv4ACL)
					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

					ginkgo.By("Bringing down NBDB")
					// inject transient problem, nbdb is down
					fakeOVN.controller.nbClient.Close()
					gomega.Eventually(func() bool {
						return fakeOVN.controller.nbClient.Connected()
					}).Should(gomega.BeFalse())

					err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Delete(context.TODO(), egressFirewall.Name, *metav1.NewDeleteOptions(0))
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					// sleep long enough for TransactWithRetry to fail, causing egress firewall Add to fail
					time.Sleep(t.OVSDBTimeout + time.Second)
					// check to see if the retry cache has an entry for this egress firewall
					key := getEgressFirewallNamespacedName(egressFirewall)
					ginkgo.By("retry entry: old obj should not be nil, new obj should be nil")
					retry.CheckRetryObjectMultipleFieldsEventually(
						key,
						fakeOVN.controller.retryEgressFirewalls,
						gomega.Not(gomega.BeNil()), // oldObj should not be nil
						gomega.BeNil(),             // newObj should be nil
					)

					connCtx, cancel := context.WithTimeout(context.Background(), t.OVSDBTimeout)
					defer cancel()
					resetNBClient(connCtx, fakeOVN.controller.nbClient)
					retry.SetRetryObjWithNoBackoff(key, fakeOVN.controller.retryEgressFirewalls)
					fakeOVN.controller.retryEgressFirewalls.RequestRetryObjs()

					// ACL should be removed from the port group after egfw is deleted
					clusterPortGroup.ACLs = []string{}
					// this ACL will be deleted when test server starts deleting dereferenced ACLs
					expectedDatabaseState = append(initialData, ipv4ACL)

					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
					// check the cache no longer has the entry
					retry.CheckRetryObjectEventually(key, false, fakeOVN.controller.retryEgressFirewalls)
					return nil
				}

				err := app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			})
			ginkgo.It(fmt.Sprintf("correctly retries adding and updating an egressfirewall, gateway mode %s", gwMode), func() {
				app.Action = func(ctx *cli.Context) error {
					namespace1 := *newNamespace("namespace1")
					egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
						{
							Type: "Allow",
							To: egressfirewallapi.EgressFirewallDestination{
								CIDRSelector: "1.2.3.4/23",
							},
						},
					})
					egressFirewall1 := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
						{
							Type: "Deny",
							To: egressfirewallapi.EgressFirewallDestination{
								CIDRSelector: "1.2.3.4/23",
							},
						},
					})

					fakeOVN.startWithDBSetup(dbSetup,
						&egressfirewallapi.EgressFirewallList{
							Items: []egressfirewallapi.EgressFirewall{
								*egressFirewall,
							},
						},
						&v1.NamespaceList{
							Items: []v1.Namespace{
								namespace1,
							},
						},
						&v1.NodeList{
							Items: []v1.Node{
								{
									Status: v1.NodeStatus{
										Phase: v1.NodeRunning,
									},
									ObjectMeta: newObjectMeta(node1Name, ""),
								},
							},
						})

					err := fakeOVN.controller.WatchNamespaces()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					err = fakeOVN.controller.WatchEgressFirewall()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					asHash, _ := getNsAddrSetHashNames(namespace1.Name)
					ipv4ACL := libovsdbops.BuildACL(
						buildEgressFwAclName("namespace1", t.EgressFirewallStartPriority),
						nbdb.ACLDirectionToLport,
						t.EgressFirewallStartPriority,
						"(ip4.dst == 1.2.3.4/23) && ip4.src == $"+asHash,
						nbdb.ACLActionAllow,
						t.OvnACLLoggingMeter,
						"",
						false,
						map[string]string{egressFirewallACLExtIdKey: "namespace1"},
						nil,
					)
					ipv4ACL.UUID = "ipv4ACL-UUID"

					// new ACL will be added to the port group
					clusterPortGroup.ACLs = []string{ipv4ACL.UUID}
					expectedDatabaseState := append(initialData, ipv4ACL)

					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
					ginkgo.By("Bringing down NBDB")
					// inject transient problem, nbdb is down
					fakeOVN.controller.nbClient.Close()
					gomega.Eventually(func() bool {
						return fakeOVN.controller.nbClient.Connected()
					}).Should(gomega.BeFalse())

					_, err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					_, err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall1.Namespace).Update(context.TODO(), egressFirewall1, metav1.UpdateOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					// sleep long enough for TransactWithRetry to fail, causing egress firewall Add to fail
					time.Sleep(t.OVSDBTimeout + time.Second)
					// check to see if the retry cache has an entry for this egress firewall
					key, err := retry.GetResourceKey(egressFirewall)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					ginkgo.By("retry entry: old obj should not be nil, new obj should not be nil")
					retry.CheckRetryObjectMultipleFieldsEventually(
						key,
						fakeOVN.controller.retryEgressFirewalls,
						gomega.Not(gomega.BeNil()), // oldObj should not be nil
						gomega.Not(gomega.BeNil()), // newObj should not be nil
					)

					connCtx, cancel := context.WithTimeout(context.Background(), t.OVSDBTimeout)
					defer cancel()
					ginkgo.By("bringing up NBDB and requesting retry of entry")
					resetNBClient(connCtx, fakeOVN.controller.nbClient)

					retry.SetRetryObjWithNoBackoff(key, fakeOVN.controller.retryEgressFirewalls)
					ginkgo.By("request immediate retry object")
					fakeOVN.controller.retryEgressFirewalls.RequestRetryObjs()
					// check the cache no longer has the entry
					retry.CheckRetryObjectEventually(key, false, fakeOVN.controller.retryEgressFirewalls)
					ipv4ACL.Action = nbdb.ACLActionDrop
					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
					return nil
				}

				err := app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

			})
			ginkgo.It(fmt.Sprintf("correctly updates an egressfirewall's ACL logging, gateway mode %s", gwMode), func() {
				app.Action = func(ctx *cli.Context) error {
					namespace1 := *newNamespace("namespace1")
					egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
						{
							Type: "Allow",
							To: egressfirewallapi.EgressFirewallDestination{
								CIDRSelector: "1.2.3.4/23",
							},
						},
					})

					fakeOVN.startWithDBSetup(dbSetup,
						&egressfirewallapi.EgressFirewallList{
							Items: []egressfirewallapi.EgressFirewall{
								*egressFirewall,
							},
						},
						&v1.NamespaceList{
							Items: []v1.Namespace{
								namespace1,
							},
						},
						&v1.NodeList{
							Items: []v1.Node{
								{
									Status: v1.NodeStatus{
										Phase: v1.NodeRunning,
									},
									ObjectMeta: newObjectMeta(node1Name, ""),
								},
							},
						})

					err := fakeOVN.controller.WatchNamespaces()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					err = fakeOVN.controller.WatchEgressFirewall()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					asHash, _ := getNsAddrSetHashNames(namespace1.Name)
					ipv4ACL := libovsdbops.BuildACL(
						buildEgressFwAclName("namespace1", t.EgressFirewallStartPriority),
						nbdb.ACLDirectionToLport,
						t.EgressFirewallStartPriority,
						"(ip4.dst == 1.2.3.4/23) && ip4.src == $"+asHash,
						nbdb.ACLActionAllow,
						t.OvnACLLoggingMeter,
						"",
						false,
						map[string]string{egressFirewallACLExtIdKey: "namespace1"},
						nil,
					)
					ipv4ACL.UUID = "ipv4ACL-UUID"

					// new ACL will be added to the port group
					clusterPortGroup.ACLs = []string{ipv4ACL.UUID}
					expectedDatabaseState := append(initialData, ipv4ACL)
					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

					// get the current namespace
					namespace, err := fakeOVN.fakeClient.KubeClient.CoreV1().Namespaces().Get(context.TODO(), namespace1.Name, metav1.GetOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					// enable ACL logging with severity alert, alert
					logSeverity := "alert"
					updatedLogSeverity := fmt.Sprintf(`{ "deny": "%s", "allow": "%s" }`, logSeverity, logSeverity)
					namespace.Annotations[util.AclLoggingAnnotation] = updatedLogSeverity
					_, err = fakeOVN.fakeClient.KubeClient.CoreV1().Namespaces().Update(context.TODO(), namespace, metav1.UpdateOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					// eventually, we should see the changes in the namespace reflected in the database
					ipv4ACL.Log = true
					ipv4ACL.Severity = &logSeverity
					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

					return nil
				}

				err := app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			})
			ginkgo.It(fmt.Sprintf("configures egress firewall correctly with node selector, gateway mode: %s", gwMode), func() {
				app.Action = func(ctx *cli.Context) error {
					config.Gateway.Mode = gwMode
					labelKey := "name"
					labelValue := "test"
					selector := metav1.LabelSelector{MatchLabels: map[string]string{labelKey: labelValue}}
					namespace1 := *newNamespace("namespace1")
					egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
						{
							Type: "Allow",
							To: egressfirewallapi.EgressFirewallDestination{
								NodeSelector: selector,
							},
						},
					})
					mdata := newObjectMeta(node1Name, "")
					mdata.Labels = map[string]string{labelKey: labelValue}
					nodeIP := "10.10.10.1"
					fakeOVN.startWithDBSetup(dbSetup,
						&egressfirewallapi.EgressFirewallList{
							Items: []egressfirewallapi.EgressFirewall{
								*egressFirewall,
							},
						},
						&v1.NamespaceList{
							Items: []v1.Namespace{
								namespace1,
							},
						},
						&v1.NodeList{
							Items: []v1.Node{
								{
									Status: v1.NodeStatus{
										Phase:     v1.NodeRunning,
										Addresses: []v1.NodeAddress{{v1.NodeInternalIP, nodeIP}},
									},
									ObjectMeta: mdata,
								},
							},
						})
					err := fakeOVN.controller.WatchNamespaces()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					err = fakeOVN.controller.WatchEgressFirewall()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					err = fakeOVN.controller.WatchEgressFwNodes()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					asHash, _ := getNsAddrSetHashNames(namespace1.Name)
					ipv4ACL := libovsdbops.BuildACL(
						buildEgressFwAclName("namespace1", t.EgressFirewallStartPriority),
						nbdb.ACLDirectionToLport,
						t.EgressFirewallStartPriority,
						fmt.Sprintf("(ip4.dst == %s) && ip4.src == $%s", nodeIP, asHash),
						nbdb.ACLActionAllow,
						t.OvnACLLoggingMeter,
						"",
						false,
						map[string]string{"egressFirewall": namespace1.Name},
						nil,
					)
					ipv4ACL.UUID = "ipv4ACL-UUID"

					clusterPortGroup.ACLs = []string{ipv4ACL.UUID}
					expectedDatabaseState := append(initialData, ipv4ACL)

					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

					return nil
				}

				err := app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			})
			ginkgo.It(fmt.Sprintf("correctly creates an egressfirewall with subnet exclusion, gateway mode %s", gwMode), func() {
				app.Action = func(ctx *cli.Context) error {
					clusterSubnetStr := "10.128.0.0/14"
					_, clusterSubnet, _ := net.ParseCIDR(clusterSubnetStr)
					config.Default.ClusterSubnets = []config.CIDRNetworkEntry{{CIDR: clusterSubnet}}

					namespace1 := *newNamespace("namespace1")
					egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
						{
							Type: "Deny",
							To: egressfirewallapi.EgressFirewallDestination{
								CIDRSelector: "0.0.0.0/0",
							},
						},
					})
					fakeOVN.startWithDBSetup(dbSetup,
						&egressfirewallapi.EgressFirewallList{
							Items: []egressfirewallapi.EgressFirewall{
								*egressFirewall,
							},
						},
						&v1.NamespaceList{
							Items: []v1.Namespace{
								namespace1,
							},
						},
						&v1.NodeList{
							Items: []v1.Node{
								{
									Status: v1.NodeStatus{
										Phase: v1.NodeRunning,
									},
									ObjectMeta: newObjectMeta(node1Name, ""),
								},
							},
						})

					err := fakeOVN.controller.WatchNamespaces()
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					_, err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					fakeOVN.controller.WatchEgressFirewall()

					asHash, _ := getNsAddrSetHashNames(namespace1.Name)
					acl := libovsdbops.BuildACL(
						buildEgressFwAclName("namespace1", t.EgressFirewallStartPriority),
						nbdb.ACLDirectionToLport,
						t.EgressFirewallStartPriority,
						"(ip4.dst == 0.0.0.0/0 && ip4.dst != "+clusterSubnetStr+") && ip4.src == $"+asHash,
						nbdb.ACLActionDrop,
						t.OvnACLLoggingMeter,
						"",
						false,
						map[string]string{egressFirewallACLExtIdKey: "namespace1"},
						nil,
					)
					acl.UUID = "acl-UUID"

					// new ACL will be added to the port group
					clusterPortGroup.ACLs = []string{acl.UUID}
					expectedDatabaseState := append(initialData, acl)
					gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

					return nil
				}
				err := app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			})
		}
	})
})

var _ = ginkgo.Describe("OVN test basic functions", func() {

	var (
		app     *cli.App
		fakeOVN *FakeOVN
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each test
		config.PrepareTestConfig()
		config.Gateway.Mode = config.GatewayModeShared
		config.OVNKubernetesFeature.EnableEgressFirewall = true

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fakeOVN = NewFakeOVN()
		fakeOVN.start()
	})

	ginkgo.AfterEach(func() {
		fakeOVN.shutdown()
	})

	ginkgo.It("computes correct L4Match", func() {
		type testcase struct {
			ports         []egressfirewallapi.EgressFirewallPort
			expectedMatch string
		}
		testcases := []testcase{
			{
				ports: []egressfirewallapi.EgressFirewallPort{
					{
						Protocol: "TCP",
						Port:     100,
					},
				},
				expectedMatch: "((tcp && ( tcp.dst == 100 )))",
			},
			{
				ports: []egressfirewallapi.EgressFirewallPort{
					{
						Protocol: "TCP",
						Port:     100,
					},
					{
						Protocol: "UDP",
					},
				},
				expectedMatch: "((udp) || (tcp && ( tcp.dst == 100 )))",
			},
			{
				ports: []egressfirewallapi.EgressFirewallPort{
					{
						Protocol: "TCP",
						Port:     100,
					},
					{
						Protocol: "SCTP",
						Port:     13,
					},
					{
						Protocol: "TCP",
						Port:     102,
					},
					{
						Protocol: "UDP",
						Port:     400,
					},
				},
				expectedMatch: "((udp && ( udp.dst == 400 )) || (tcp && ( tcp.dst == 100 || tcp.dst == 102 )) || (sctp && ( sctp.dst == 13 )))",
			},
		}
		for _, test := range testcases {
			l4Match := egressGetL4Match(test.ports)
			gomega.Expect(test.expectedMatch).To(gomega.Equal(l4Match))
		}
	})
	ginkgo.It("computes correct match function", func() {
		type testcase struct {
			clusterSubnets []string
			ipv4source     string
			ipv6source     string
			ipv4Mode       bool
			ipv6Mode       bool
			destinations   []matchTarget
			ports          []egressfirewallapi.EgressFirewallPort
			output         string
		}
		testcases := []testcase{
			{
				clusterSubnets: []string{"10.128.0.0/14"},
				ipv4source:     "testv4",
				ipv6source:     "",
				ipv4Mode:       true,
				ipv6Mode:       false,
				destinations:   []matchTarget{{matchKindV4CIDR, "1.2.3.4/32", false}},
				ports:          nil,
				output:         "(ip4.dst == 1.2.3.4/32) && ip4.src == $testv4",
			},
			{
				clusterSubnets: []string{"10.128.0.0/14", "2002:0:0:1234::/64"},
				ipv4source:     "testv4",
				ipv6source:     "testv6",
				ipv4Mode:       true,
				ipv6Mode:       true,
				destinations:   []matchTarget{{matchKindV4CIDR, "1.2.3.4/32", false}},
				ports:          nil,
				output:         "(ip4.dst == 1.2.3.4/32) && ip4.src == $testv4",
			},
			{
				clusterSubnets: []string{"10.128.0.0/14", "2002:0:0:1234::/64"},
				ipv4source:     "testv4",
				ipv6source:     "testv6",
				ipv4Mode:       true,
				ipv6Mode:       true,
				destinations:   []matchTarget{{matchKindV4AddressSet, "destv4", false}, {matchKindV6AddressSet, "destv6", false}},
				ports:          nil,
				output:         "(ip4.dst == $destv4 || ip6.dst == $destv6) && (ip4.src == $testv4 || ip6.src == $testv6)",
			},
			{
				clusterSubnets: []string{"10.128.0.0/14"},
				ipv4source:     "testv4",
				ipv6source:     "",
				ipv4Mode:       true,
				ipv6Mode:       false,
				destinations:   []matchTarget{{matchKindV4AddressSet, "destv4", false}, {matchKindV6AddressSet, "", false}},
				ports:          nil,
				output:         "(ip4.dst == $destv4) && ip4.src == $testv4",
			},
			{
				clusterSubnets: []string{"10.128.0.0/14", "2002:0:0:1234::/64"},
				ipv4source:     "testv4",
				ipv6source:     "testv6",
				ipv4Mode:       true,
				ipv6Mode:       true,
				destinations:   []matchTarget{{matchKindV6CIDR, "2001::/64", false}},
				ports:          nil,
				output:         "(ip6.dst == 2001::/64) && ip6.src == $testv6",
			},
			{
				clusterSubnets: []string{"2002:0:0:1234::/64"},
				ipv4source:     "",
				ipv6source:     "testv6",
				ipv4Mode:       false,
				ipv6Mode:       true,
				destinations:   []matchTarget{{matchKindV6AddressSet, "destv6", false}},
				ports:          nil,
				output:         "(ip6.dst == $destv6) && ip6.src == $testv6",
			},
			// with cluster subnet exclusion
			{
				clusterSubnets: []string{"10.128.0.0/14"},
				ipv4source:     "testv4",
				ipv6source:     "",
				ipv4Mode:       true,
				ipv6Mode:       false,
				destinations:   []matchTarget{{matchKindV4CIDR, "1.2.3.4/32", true}},
				ports:          nil,
				output:         "(ip4.dst == 1.2.3.4/32 && ip4.dst != 10.128.0.0/14) && ip4.src == $testv4",
			},
			{
				clusterSubnets: []string{"2002:0:0:1234::/64"},
				ipv4source:     "",
				ipv6source:     "testv6",
				ipv4Mode:       false,
				ipv6Mode:       true,
				destinations:   []matchTarget{{matchKindV6AddressSet, "destv6", true}},
				ports:          nil,
				output:         "(ip6.dst == $destv6) && ip6.src == $testv6",
			},
			{
				clusterSubnets: []string{"10.128.0.0/14", "2002:0:0:1234::/64"},
				ipv4source:     "testv4",
				ipv6source:     "testv6",
				ipv4Mode:       true,
				ipv6Mode:       true,
				destinations:   []matchTarget{{matchKindV4CIDR, "1.2.3.4/32", true}},
				ports:          nil,
				output:         "(ip4.dst == 1.2.3.4/32 && ip4.dst != 10.128.0.0/14) && ip4.src == $testv4",
			},
		}

		for _, tc := range testcases {
			config.IPv4Mode = tc.ipv4Mode
			config.IPv6Mode = tc.ipv6Mode
			subnets := []config.CIDRNetworkEntry{}
			for _, clusterCIDR := range tc.clusterSubnets {
				_, cidr, _ := net.ParseCIDR(clusterCIDR)
				subnets = append(subnets, config.CIDRNetworkEntry{CIDR: cidr})
			}
			config.Default.ClusterSubnets = subnets

			config.Gateway.Mode = config.GatewayModeShared
			matchExpression := generateMatch(tc.ipv4source, tc.ipv6source, tc.destinations, tc.ports)
			gomega.Expect(matchExpression).To(gomega.Equal(tc.output))
		}
	})
	ginkgo.It("correctly parses egressFirewallRules", func() {
		type testcase struct {
			egressFirewallRule egressfirewallapi.EgressFirewallRule
			id                 int
			err                bool
			errOutput          string
			output             egressFirewallRule
			clusterSubnets     []string
		}
		testcases := []testcase{
			{
				egressFirewallRule: egressfirewallapi.EgressFirewallRule{
					Type: egressfirewallapi.EgressFirewallRuleAllow,
					To:   egressfirewallapi.EgressFirewallDestination{CIDRSelector: "1.2.3.4/32"},
				},
				id:  1,
				err: false,
				output: egressFirewallRule{
					id:     1,
					access: egressfirewallapi.EgressFirewallRuleAllow,
					to:     destination{cidrSelector: "1.2.3.4/32"},
				},
			},
			{
				clusterSubnets: []string{"10.128.0.0/16"},
				egressFirewallRule: egressfirewallapi.EgressFirewallRule{
					Type: egressfirewallapi.EgressFirewallRuleAllow,
					To:   egressfirewallapi.EgressFirewallDestination{CIDRSelector: "1.2.3./32"},
				},
				id:        1,
				err:       true,
				errOutput: "invalid CIDR address: 1.2.3./32",
				output:    egressFirewallRule{},
			},
			{
				clusterSubnets: []string{"2002:0:0:1234::/64"},
				egressFirewallRule: egressfirewallapi.EgressFirewallRule{
					Type: egressfirewallapi.EgressFirewallRuleAllow,
					To:   egressfirewallapi.EgressFirewallDestination{CIDRSelector: "2002::1235:abcd:ffff:c0a8:101/64"},
				},
				id:  2,
				err: false,
				output: egressFirewallRule{
					id:     2,
					access: egressfirewallapi.EgressFirewallRuleAllow,
					to:     destination{cidrSelector: "2002::1235:abcd:ffff:c0a8:101/64"},
				},
			},
			// check clusterSubnet intersection
			{
				clusterSubnets: []string{"10.128.0.0/16"},
				egressFirewallRule: egressfirewallapi.EgressFirewallRule{
					Type: egressfirewallapi.EgressFirewallRuleAllow,
					To:   egressfirewallapi.EgressFirewallDestination{CIDRSelector: "1.2.3.4/32"},
				},
				id:  1,
				err: false,
				output: egressFirewallRule{
					id:     1,
					access: egressfirewallapi.EgressFirewallRuleAllow,
					to:     destination{cidrSelector: "1.2.3.4/32", clusterSubnetIntersection: false},
				},
			},
			{
				clusterSubnets: []string{"10.128.0.0/16"},
				egressFirewallRule: egressfirewallapi.EgressFirewallRule{
					Type: egressfirewallapi.EgressFirewallRuleAllow,
					To:   egressfirewallapi.EgressFirewallDestination{CIDRSelector: "10.128.3.4/32"},
				},
				id:  1,
				err: false,
				output: egressFirewallRule{
					id:     1,
					access: egressfirewallapi.EgressFirewallRuleAllow,
					to:     destination{cidrSelector: "10.128.3.4/32", clusterSubnetIntersection: true},
				},
			},
			{
				clusterSubnets: []string{"10.128.0.0/16"},
				egressFirewallRule: egressfirewallapi.EgressFirewallRule{
					Type: egressfirewallapi.EgressFirewallRuleAllow,
					To:   egressfirewallapi.EgressFirewallDestination{CIDRSelector: "10.128.3.0/24"},
				},
				id:  1,
				err: false,
				output: egressFirewallRule{
					id:     1,
					access: egressfirewallapi.EgressFirewallRuleAllow,
					to:     destination{cidrSelector: "10.128.3.0/24", clusterSubnetIntersection: true},
				},
			},
			{
				clusterSubnets: []string{"2002:0:0:1234::/64"},
				egressFirewallRule: egressfirewallapi.EgressFirewallRule{
					Type: egressfirewallapi.EgressFirewallRuleAllow,
					To:   egressfirewallapi.EgressFirewallDestination{CIDRSelector: "2002:0:0:1234:0001::/80"},
				},
				id:  1,
				err: false,
				output: egressFirewallRule{
					id:     1,
					access: egressfirewallapi.EgressFirewallRuleAllow,
					to:     destination{cidrSelector: "2002:0:0:1234:0001::/80", clusterSubnetIntersection: true},
				},
			},
			{
				clusterSubnets: []string{"2002:0:0:1234::/64"},
				egressFirewallRule: egressfirewallapi.EgressFirewallRule{
					Type: egressfirewallapi.EgressFirewallRuleAllow,
					To:   egressfirewallapi.EgressFirewallDestination{CIDRSelector: "2002:0:0:1235::/80"},
				},
				id:  1,
				err: false,
				output: egressFirewallRule{
					id:     1,
					access: egressfirewallapi.EgressFirewallRuleAllow,
					to:     destination{cidrSelector: "2002:0:0:1235::/80", clusterSubnetIntersection: false},
				},
			},
			// dual stack
			{
				clusterSubnets: []string{"10.128.0.0/16", "2002:0:0:1234::/64"},
				egressFirewallRule: egressfirewallapi.EgressFirewallRule{
					Type: egressfirewallapi.EgressFirewallRuleAllow,
					To:   egressfirewallapi.EgressFirewallDestination{CIDRSelector: "10.128.3.4/32"},
				},
				id:  1,
				err: false,
				output: egressFirewallRule{
					id:     1,
					access: egressfirewallapi.EgressFirewallRuleAllow,
					to:     destination{cidrSelector: "10.128.3.4/32", clusterSubnetIntersection: true},
				},
			},
			{
				clusterSubnets: []string{"10.128.0.0/16", "2002:0:0:1234::/64"},
				egressFirewallRule: egressfirewallapi.EgressFirewallRule{
					Type: egressfirewallapi.EgressFirewallRuleAllow,
					To:   egressfirewallapi.EgressFirewallDestination{CIDRSelector: "2002:0:0:1234:0001::/80"},
				},
				id:  1,
				err: false,
				output: egressFirewallRule{
					id:     1,
					access: egressfirewallapi.EgressFirewallRuleAllow,
					to:     destination{cidrSelector: "2002:0:0:1234:0001::/80", clusterSubnetIntersection: true},
				},
			},
			{
				egressFirewallRule: egressfirewallapi.EgressFirewallRule{
					Type: egressfirewallapi.EgressFirewallRuleAllow,
					To:   egressfirewallapi.EgressFirewallDestination{NodeSelector: metav1.LabelSelector{}},
				},
				id:  1,
				err: false,
				output: egressFirewallRule{
					id:     1,
					access: egressfirewallapi.EgressFirewallRuleAllow,
					to:     destination{nodeAddrs: sets.NewString()},
				},
			},
		}
		for _, tc := range testcases {
			subnets := []config.CIDRNetworkEntry{}
			for _, clusterCIDR := range tc.clusterSubnets {
				_, cidr, _ := net.ParseCIDR(clusterCIDR)
				subnets = append(subnets, config.CIDRNetworkEntry{CIDR: cidr})
			}
			config.Default.ClusterSubnets = subnets
			output, err := fakeOVN.controller.newEgressFirewallRule(tc.egressFirewallRule, tc.id)
			if tc.err == true {
				gomega.Expect(err).To(gomega.HaveOccurred())
				gomega.Expect(tc.errOutput).To(gomega.Equal(err.Error()))
			} else {
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(*output).To(gomega.Equal(tc.output))
			}
		}
	})
})

//helper functions to help test egressfirewallDNS

// Create an EgressDNS object without the Sync function
// To make it easier to mock EgressFirewall functionality create an egressFirewall
// without the go routine of the sync function

// GetDNSEntryForTest Gets a dnsEntry from a EgressDNS object for testing
func (e *EgressDNS) GetDNSEntryForTest(dnsName string) (map[string]struct{}, []net.IP, addressset.AddressSet, error) {
	if e.dnsEntries[dnsName] == nil {
		return nil, nil, nil, fmt.Errorf("there is no dnsEntry for dnsName: %s", dnsName)
	}
	return e.dnsEntries[dnsName].namespaces, e.dnsEntries[dnsName].dnsResolves, e.dnsEntries[dnsName].dnsAddressSet, nil
}
