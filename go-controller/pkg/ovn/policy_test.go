package ovn

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"

	//"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/urfave/cli/v2"

	v1 "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type ipMode struct {
	IPv4Mode bool
	IPv6Mode bool
}

// FIXME DUAL-STACK: FakeOVN doesn't really support adding more than one
// pod to the namespace. All logical ports would share the same fakeUUID.
// When this is addressed we can add an entry for
// IPv4Mode = true, IPv6Mode = true.
func getIpModes() []ipMode {
	return []ipMode{
		{true, false},
		{false, true},
	}
}

func ipModeStr(m ipMode) string {
	return fmt.Sprintf("(IPv4 %t IPv6 %t)", m.IPv4Mode, m.IPv6Mode)
}

func setIpMode(m ipMode) {
	config.IPv4Mode = m.IPv4Mode
	config.IPv6Mode = m.IPv6Mode
}

type kNetworkPolicy struct{}

func newNetworkPolicyMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		UID:       apimachinerytypes.UID(namespace),
		Name:      name,
		Namespace: namespace,
		Labels: map[string]string{
			"name": name,
		},
	}
}

func newNetworkPolicy(name, namespace string, podSelector metav1.LabelSelector, ingress []knet.NetworkPolicyIngressRule, egress []knet.NetworkPolicyEgressRule) *knet.NetworkPolicy {
	return &knet.NetworkPolicy{
		ObjectMeta: newNetworkPolicyMeta(name, namespace),
		Spec: knet.NetworkPolicySpec{
			PodSelector: podSelector,
			Ingress:     ingress,
			Egress:      egress,
		},
	}
}

func (n kNetworkPolicy) baseCmds(fexec *ovntest.FakeExec, networkPolicy *knet.NetworkPolicy) string {
	readableGroupName := fmt.Sprintf("%s_%s", networkPolicy.Namespace, networkPolicy.Name)
	return readableGroupName
}

const (
	ingressDenyPG string = "ingressDefaultDeny"
	egressDenyPG  string = "egressDefaultDeny"
)

func (n kNetworkPolicy) addDefaultDenyPGCmds(fexec *ovntest.FakeExec, networkPolicy *knet.NetworkPolicy) {
	pg_hash := hashedPortGroup(networkPolicy.Namespace)
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"outport == @" + pg_hash + "_" + ingressDenyPG + "\" action=drop external-ids:default-deny-policy-type=Ingress",
		Output: fakeUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"outport == @" + pg_hash + "_" + ingressDenyPG + " && arp\" action=allow external-ids:default-deny-policy-type=Ingress",
		Output: fakeUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"inport == @" + pg_hash + "_" + egressDenyPG + "\" action=drop external-ids:default-deny-policy-type=Egress",
		Output: fakeUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"inport == @" + pg_hash + "_" + egressDenyPG + " && arp\" action=allow external-ids:default-deny-policy-type=Egress",
		Output: fakeUUID,
	})
}

func (n kNetworkPolicy) addLocalPodCmds(fexec *ovntest.FakeExec, networkPolicy *knet.NetworkPolicy) {
	n.addDefaultDenyPGCmds(fexec, networkPolicy)
}

func (n kNetworkPolicy) addNamespaceSelectorCmds(fexec *ovntest.FakeExec, networkPolicy *knet.NetworkPolicy, namespace string) {
	as := []string{}
	if namespace != "" {
		as = append(as, namespace)
	}

	for i := range networkPolicy.Spec.Ingress {
		ingressAsMatch := asMatch(append(as, getAddressSetName(networkPolicy.Namespace, networkPolicy.Name, knet.PolicyTypeIngress, i)))
		fexec.AddFakeCmdsNoOutputNoError([]string{
			fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Ingress_num=%v external-ids:policy_type=Ingress", networkPolicy.Namespace, networkPolicy.Name, i),
			"ovn-nbctl --timeout=15 --id=@acl create acl priority=" + types.DefaultAllowPriority + " direction=" + types.DirectionToLPort + " match=\"ip4.src == {" + ingressAsMatch + "} && outport == @a14195333570786048679\" action=allow-related log=false severity=info meter=acl-logging name=" + networkPolicy.Namespace + "_" + networkPolicy.Name + "_" + strconv.Itoa(i) + " external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Ingress_num=0 external-ids:policy_type=Ingress -- add port_group " + fakePgUUID + " acls @acl",
		})
	}
	for i := range networkPolicy.Spec.Egress {
		egressAsMatch := asMatch(append(as, getAddressSetName(networkPolicy.Namespace, networkPolicy.Name, knet.PolicyTypeEgress, i)))
		fexec.AddFakeCmdsNoOutputNoError([]string{
			fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Egress_num=%v external-ids:policy_type=Egress", networkPolicy.Namespace, networkPolicy.Name, i),
			"ovn-nbctl --timeout=15 --id=@acl create acl priority=" + types.DefaultAllowPriority + " direction=" + types.DirectionToLPort + " match=\"ip4.dst == {" + egressAsMatch + "} && inport == @a14195333570786048679\" action=allow-related log=false severity=info meter=acl-logging name=" + networkPolicy.Namespace + "_" + networkPolicy.Name + "_" + strconv.Itoa(i) + " external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Egress_num=0 external-ids:policy_type=Egress -- add port_group " + fakePgUUID + " acls @acl",
		})
	}
}

func (n kNetworkPolicy) addNamespaceSelectorCmdsExistingAcl(fexec *ovntest.FakeExec, networkPolicy *knet.NetworkPolicy, namespace string) {
	for i := range networkPolicy.Spec.Ingress {
		ingressAsMatch := asMatch([]string{
			namespace,
			getAddressSetName(networkPolicy.Namespace, networkPolicy.Name, knet.PolicyTypeIngress, i),
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Ingress_num=%v external-ids:policy_type=Ingress", networkPolicy.Namespace, networkPolicy.Name, i),
			Output: fakeUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 set acl " + fakeUUID + " match=\"ip4.src == {" + ingressAsMatch + "} && outport == @a14195333570786048679\" priority=" + types.DefaultAllowPriority + " direction=" + types.DirectionToLPort + " action=allow-related log=false severity=info meter=acl-logging name=" + networkPolicy.Namespace + "_" + networkPolicy.Name + "_" + strconv.Itoa(i),
		})
	}
	for i := range networkPolicy.Spec.Egress {
		egressAsMatch := asMatch([]string{
			namespace,
			getAddressSetName(networkPolicy.Namespace, networkPolicy.Name, knet.PolicyTypeEgress, i),
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Egress_num=%v external-ids:policy_type=Egress", networkPolicy.Namespace, networkPolicy.Name, i),
			Output: fakeUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 set acl " + fakeUUID + " match=\"ip4.dst == {" + egressAsMatch + "} && inport == @a14195333570786048679\" priority=" + types.DefaultAllowPriority + " direction=" + types.DirectionToLPort + " action=allow-related log=false severity=info meter=acl-logging name=" + networkPolicy.Namespace + "_" + networkPolicy.Name + "_" + strconv.Itoa(i),
		})
	}
}

func getAddressSetName(namespace, name string, policyType knet.PolicyType, idx int) string {
	direction := strings.ToLower(string(policyType))
	return fmt.Sprintf("%s.%s.%s.%d", namespace, name, direction, idx)
}

func eventuallyExpectNoAddressSets(fakeOvn *FakeOVN, networkPolicy *knet.NetworkPolicy) {
	for i := range networkPolicy.Spec.Ingress {
		asName := getAddressSetName(networkPolicy.Namespace, networkPolicy.Name, knet.PolicyTypeIngress, i)
		fakeOvn.asf.EventuallyExpectNoAddressSet(asName)
	}
	for i := range networkPolicy.Spec.Egress {
		asName := getAddressSetName(networkPolicy.Namespace, networkPolicy.Name, knet.PolicyTypeEgress, i)
		fakeOvn.asf.EventuallyExpectNoAddressSet(asName)
	}
}

func expectAddressSetsWithIP(fakeOvn *FakeOVN, networkPolicy *knet.NetworkPolicy, ip string) {
	for i := range networkPolicy.Spec.Ingress {
		asName := getAddressSetName(networkPolicy.Namespace, networkPolicy.Name, knet.PolicyTypeIngress, i)
		fakeOvn.asf.ExpectAddressSetWithIPs(asName, []string{ip})
	}
	for i := range networkPolicy.Spec.Egress {
		asName := getAddressSetName(networkPolicy.Namespace, networkPolicy.Name, knet.PolicyTypeEgress, i)
		fakeOvn.asf.ExpectAddressSetWithIPs(asName, []string{ip})
	}
}

func eventuallyExpectEmptyAddressSets(fakeOvn *FakeOVN, networkPolicy *knet.NetworkPolicy) {
	for i := range networkPolicy.Spec.Ingress {
		asName := getAddressSetName(networkPolicy.Namespace, networkPolicy.Name, knet.PolicyTypeIngress, i)
		fakeOvn.asf.EventuallyExpectEmptyAddressSet(asName)
	}
	for i := range networkPolicy.Spec.Egress {
		asName := getAddressSetName(networkPolicy.Namespace, networkPolicy.Name, knet.PolicyTypeEgress, i)
		fakeOvn.asf.EventuallyExpectEmptyAddressSet(asName)
	}
}

type multicastPolicy struct{}

func (p multicastPolicy) enableCmds(fExec *ovntest.FakeExec, ns string) {
	pg_hash := hashedPortGroup(ns)

	match := getACLMatch(pg_hash, getMulticastACLEgrMatch(), knet.PolicyTypeEgress)
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL " +
			match + " action=allow external-ids:default-deny-policy-type=Egress",
	})
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --id=@acl create acl priority=" + types.DefaultMcastAllowPriority + " direction=" + types.DirectionFromLPort + " " +
			match + " action=allow log=false severity=info meter=acl-logging name=namespace1_MulticastAllowEgress external-ids:default-deny-policy-type=Egress " +
			"-- add port_group " + fakePgUUID + " acls @acl",
	})

	ip4AddressSet, ip6AddressSet := addressset.MakeAddressSetHashNames(ns)
	mcastMatch := getACLMatchAF(getMulticastACLIgrMatchV4(ip4AddressSet),
		getMulticastACLIgrMatchV6(ip6AddressSet))
	match = getACLMatch(pg_hash, mcastMatch, knet.PolicyTypeIngress)
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL " +
			match + " action=allow external-ids:default-deny-policy-type=Ingress",
	})
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --id=@acl create acl priority=" + types.DefaultMcastAllowPriority + " direction=" + types.DirectionToLPort + " " +
			match + " action=allow log=false severity=info meter=acl-logging name=namespace1_MulticastAllowIngress external-ids:default-deny-policy-type=Ingress " +
			"-- add port_group " + fakePgUUID + " acls @acl",
	})
}

func (p multicastPolicy) getACLMatch(ns string) (ingressMatch, egressMatch string) {
	pg_hash := hashedPortGroup(ns)
	egressMatch = getACLMatch(pg_hash, getMulticastACLEgrMatch(), knet.PolicyTypeEgress)

	ip4AddressSet, ip6AddressSet := addressset.MakeAddressSetHashNames(ns)
	mcastMatch := getACLMatchAF(getMulticastACLIgrMatchV4(ip4AddressSet), getMulticastACLIgrMatchV6(ip6AddressSet))
	ingressMatch = getACLMatch(pg_hash, mcastMatch, knet.PolicyTypeIngress)
	return
}

var _ = ginkgo.Describe("OVN NetworkPolicy Operations with IP Address Family", func() {
	const (
		namespaceName1 = "namespace1"
		namespaceName2 = "namespace2"
	)
	var (
		app     *cli.App
		fakeOvn *FakeOVN
		fExec   *ovntest.FakeExec
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()
		config.IPv4Mode = true
		config.IPv6Mode = false

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fExec = ovntest.NewLooseCompareFakeExec()
		fakeOvn = NewFakeOVN(fExec)
		ovntest.ResetNumMockExecutions()
	})

	ginkgo.AfterEach(func() {
		fakeOvn.shutdown()
	})

	ginkgo.Context("during execution", func() {
		for _, m := range getIpModes() {
			m := m
			ginkgo.It("tests enabling/disabling multicast in a namespace "+ipModeStr(m), func() {
				app.Action = func(ctx *cli.Context) error {
					namespace1 := *newNamespace(namespaceName1)

					fakeOvn.start(ctx,
						&v1.NamespaceList{
							Items: []v1.Namespace{
								namespace1,
							},
						},
					)
					setIpMode(m)

					fakeOvn.controller.WatchNamespaces()
					ns, err := fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Get(
						context.TODO(), namespace1.Name, metav1.GetOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Expect(ns).NotTo(gomega.BeNil())

					// Multicast is denied by default.
					_, ok := ns.Annotations[nsMulticastAnnotation]
					gomega.Expect(ok).To(gomega.BeFalse())

					// Enable multicast in the namespace.
					mcastPolicy := multicastPolicy{}
					ingressMatch, egressMatch := mcastPolicy.getACLMatch(namespace1.Name)
					expectedData := []libovsdb.TestData{
						&nbdb.ACL{
							UUID:      namespace1.Name + "_MulticastAllowEgress",
							Name:      []string{namespace1.Name + "_MulticastAllowEgress"},
							Priority:  1012,
							Direction: nbdb.ACLDirectionFromLport,
							Match:     egressMatch,
							Action:    nbdb.ACLActionAllow,
							Log:       false,
							Meter:     []string{"acl-logging"},
							Severity:  []string{nbdb.ACLSeverityInfo},
							ExternalIDs: map[string]string{
								"default-deny-policy-type": "Egress",
							},
						},
						&nbdb.ACL{
							UUID:      namespace1.Name + "_MulticastAllowIngress",
							Name:      []string{namespace1.Name + "_MulticastAllowIngress"},
							Priority:  1012,
							Direction: nbdb.ACLDirectionToLport,
							Match:     ingressMatch,
							Action:    nbdb.ACLActionAllow,
							Log:       false,
							Meter:     []string{"acl-logging"},
							Severity:  []string{nbdb.ACLSeverityInfo},
							ExternalIDs: map[string]string{
								"default-deny-policy-type": "Ingress",
							},
						},
						&nbdb.PortGroup{
							UUID: namespace1.Name,
							Name: hashedPortGroup(namespace1.Name),
							ACLs: []string{
								namespace1.Name + "_MulticastAllowEgress",
								namespace1.Name + "_MulticastAllowIngress",
							},
							ExternalIDs: map[string]string{
								"name": namespace1.Name,
							},
						},
					}

					ns.Annotations[nsMulticastAnnotation] = "true"
					_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Eventually(fakeOvn.nbClient).Should(libovsdb.HaveTestData(expectedData...))

					// Disable multicast in the namespace.
					ns.Annotations[nsMulticastAnnotation] = "false"
					_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Eventually(fakeOvn.nbClient).Should(libovsdb.HaveTestData(expectedData[0], expectedData[1]))
					return nil
				}

				err := app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			})

			ginkgo.It("tests enabling multicast in a namespace with a pod "+ipModeStr(m), func() {
				app.Action = func(ctx *cli.Context) error {
					namespace1 := *newNamespace(namespaceName1)
					nPodTestV4 := newTPod(
						"node1",
						"10.128.1.0/24",
						"10.128.1.2",
						"10.128.1.1",
						"myPod1",
						"10.128.1.3",
						"0a:58:0a:80:01:03",
						namespace1.Name,
					)
					nPodTestV6 := newTPod(
						"node1",
						"fd00:10:244::/64",
						"fd00:10:244::2",
						"fd00:10:244::1",
						"myPod2",
						"fd00:10:244::3",
						"0a:58:0a:80:02:03",
						namespace1.Name,
					)
					var tPods []pod
					var tPodIPs []string
					if m.IPv4Mode {
						tPods = append(tPods, nPodTestV4)
						tPodIPs = append(tPodIPs, nPodTestV4.podIP)
					}
					if m.IPv6Mode {
						tPods = append(tPods, nPodTestV6)
						tPodIPs = append(tPodIPs, nPodTestV6.podIP)
					}

					var pods []v1.Pod
					for _, tPod := range tPods {
						pods = append(pods,
							*newPod(tPod.namespace, tPod.podName, tPod.nodeName, tPod.podIP))
						tPod.baseCmds(fExec)
					}

					fakeOvn.start(ctx,
						&v1.NamespaceList{
							Items: []v1.Namespace{
								namespace1,
							},
						},
						&v1.PodList{
							Items: pods,
						},
					)
					setIpMode(m)

					for _, tPod := range tPods {
						tPod.populateLogicalSwitchCache(fakeOvn)
					}
					fakeOvn.controller.WatchNamespaces()
					fakeOvn.controller.WatchPods()
					ns, err := fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Get(
						context.TODO(), namespace1.Name, metav1.GetOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Expect(ns).NotTo(gomega.BeNil())
					gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
					// Enable multicast in the namespace
					mcastPolicy := multicastPolicy{}
					mcastPolicy.enableCmds(fExec, namespace1.Name)
					ns.Annotations[nsMulticastAnnotation] = "true"
					_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
					fakeOvn.asf.ExpectAddressSetWithIPs(namespace1.Name, tPodIPs)
					return nil
				}

				err := app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			})

			ginkgo.It("tests adding a pod to a multicast enabled namespace "+ipModeStr(m), func() {
				app.Action = func(ctx *cli.Context) error {
					namespace1 := *newNamespace(namespaceName1)
					nPodTestV4 := newTPod(
						"node1",
						"10.128.1.0/24",
						"10.128.1.2",
						"10.128.1.1",
						"myPod1",
						"10.128.1.3",
						"0a:58:0a:80:01:03",
						namespace1.Name,
					)
					nPodTestV6 := newTPod(
						"node1",
						"fd00:10:244::/64",
						"fd00:10:244::2",
						"fd00:10:244::1",
						"myPod2",
						"fd00:10:244::3",
						"0a:58:0a:80:02:03",
						namespace1.Name,
					)
					var tPods []pod
					var tPodIPs []string
					if m.IPv4Mode {
						tPods = append(tPods, nPodTestV4)
						tPodIPs = append(tPodIPs, nPodTestV4.podIP)
					}
					if m.IPv6Mode {
						tPods = append(tPods, nPodTestV6)
						tPodIPs = append(tPodIPs, nPodTestV6.podIP)
					}

					fakeOvn.start(ctx,
						&v1.NamespaceList{
							Items: []v1.Namespace{
								namespace1,
							},
						},
					)
					setIpMode(m)

					for _, tPod := range tPods {
						tPod.baseCmds(fExec)
					}
					fakeOvn.controller.WatchNamespaces()
					fakeOvn.controller.WatchPods()
					ns, err := fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Get(
						context.TODO(), namespace1.Name, metav1.GetOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Expect(ns).NotTo(gomega.BeNil())

					// Enable multicast in the namespace.
					mcastPolicy := multicastPolicy{}
					mcastPolicy.enableCmds(fExec, namespace1.Name)
					ns.Annotations[nsMulticastAnnotation] = "true"
					_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

					for _, tPod := range tPods {
						tPod.populateLogicalSwitchCache(fakeOvn)

						_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(tPod.namespace).Create(context.TODO(), newPod(
							tPod.namespace, tPod.podName, tPod.nodeName, tPod.podIP), metav1.CreateOptions{})
						gomega.Expect(err).NotTo(gomega.HaveOccurred())

					}

					gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
					gomega.Eventually(ovntest.GetNumMockExecutions, 2).Should(gomega.BeNumerically("==", 7), fExec.ErrorDesc)
					fakeOvn.asf.ExpectAddressSetWithIPs(namespace1.Name, tPodIPs)

					for _, tPod := range tPods {
						// Delete the pod from the namespace.
						err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(tPod.namespace).Delete(context.TODO(),
							tPod.podName, *metav1.NewDeleteOptions(0))
						gomega.Expect(err).NotTo(gomega.HaveOccurred())
					}

					gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
					gomega.Eventually(ovntest.GetNumMockExecutions, 2).Should(gomega.BeNumerically("==", 9), fExec.ErrorDesc)
					fakeOvn.asf.ExpectEmptyAddressSet(namespace1.Name)
					return nil
				}

				err := app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			})
		}
	})
})

var _ = ginkgo.Describe("OVN NetworkPolicy Operations", func() {
	const (
		namespaceName1 = "namespace1"

		namespaceName2 = "namespace2"
	)
	var (
		app     *cli.App
		fakeOvn *FakeOVN
		fExec   *ovntest.FakeExec
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fExec = ovntest.NewLooseCompareFakeExec()
		fakeOvn = NewFakeOVN(fExec)
	})

	ginkgo.AfterEach(func() {
		fakeOvn.shutdown()
	})

	ginkgo.Context("on startup", func() {

		ginkgo.It("reconciles an existing ingress networkPolicy with a namespace selector", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := kNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					})

				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, namespace2.Name)
				npTest.addDefaultDenyPGCmds(fExec, networkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)

				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				fakeOvn.asf.ExpectEmptyAddressSet(namespaceName1)
				fakeOvn.asf.ExpectEmptyAddressSet(namespaceName2)

				eventuallyExpectEmptyAddressSets(fakeOvn, networkPolicy)

				_, err := fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("reconciles an ingress networkPolicy updating an existing ACL", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := kNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					})

				npTest.addNamespaceSelectorCmdsExistingAcl(fExec, networkPolicy, namespace2.Name)
				npTest.addDefaultDenyPGCmds(fExec, networkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)

				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				fakeOvn.asf.ExpectEmptyAddressSet(namespaceName1)
				fakeOvn.asf.ExpectEmptyAddressSet(namespaceName2)

				eventuallyExpectEmptyAddressSets(fakeOvn, networkPolicy)

				_, err := fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("reconciles an existing gress networkPolicy with a pod selector in its own namespace", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := kNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace1.Name,
				)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, "")
				npTest.addLocalPodCmds(fExec, networkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNetworkPolicy()

				expectAddressSetsWithIP(fakeOvn, networkPolicy, nPodTest.podIP)
				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName1, []string{nPodTest.podIP})

				_, err := fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("reconciles an existing gress networkPolicy with a pod and namespace selector in another namespace", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := kNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)

				nPodTest := newTPod(
					"node2",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace2.Name,
				)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, "")
				npTest.addDefaultDenyPGCmds(fExec, networkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNetworkPolicy()

				fakeOvn.asf.ExpectEmptyAddressSet(namespaceName1)
				expectAddressSetsWithIP(fakeOvn, networkPolicy, nPodTest.podIP)
				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName2, []string{nPodTest.podIP})

				_, err := fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("during execution", func() {

		ginkgo.It("correctly creates and deletes a networkpolicy allowing a port to a local pod", func() {
			app.Action = func(ctx *cli.Context) error {
				npTest := kNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace1.Name,
				)
				nPod := newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP)

				const (
					labelName string = "pod-name"
					labelVal  string = "server"
					portNum   int32  = 81
				)
				nPod.Labels[labelName] = labelVal

				tcpProtocol := v1.Protocol(v1.ProtocolTCP)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{
						MatchLabels: map[string]string{
							labelName: labelVal,
						},
					},
					[]knet.NetworkPolicyIngressRule{{
						Ports: []knet.NetworkPolicyPort{{
							Port:     &intstr.IntOrString{IntVal: portNum},
							Protocol: &tcpProtocol,
						}},
					}},
					[]knet.NetworkPolicyEgressRule{{
						Ports: []knet.NetworkPolicyPort{{
							Port:     &intstr.IntOrString{IntVal: portNum},
							Protocol: &tcpProtocol,
						}},
					}},
				)

				// This is not yet going to be created
				networkPolicy2 := newNetworkPolicy("networkpolicy2", namespace1.Name,
					metav1.LabelSelector{
						MatchLabels: map[string]string{
							labelName: labelVal,
						},
					},
					[]knet.NetworkPolicyIngressRule{{
						Ports: []knet.NetworkPolicyPort{{
							Port:     &intstr.IntOrString{IntVal: portNum + 1},
							Protocol: &tcpProtocol,
						}},
					}},
					[]knet.NetworkPolicyEgressRule{{
						Ports: []knet.NetworkPolicyPort{{
							Port:     &intstr.IntOrString{IntVal: portNum + 1},
							Protocol: &tcpProtocol,
						}},
					}},
				)

				nPodTest.baseCmds(fExec)
				npTest.baseCmds(fExec, networkPolicy)
				npTest.addLocalPodCmds(fExec, networkPolicy)

				fExec.AddFakeCmdsNoOutputNoError([]string{
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"tcp && tcp.dst==%d\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Ingress_num=0 external-ids:policy_type=Ingress", portNum, networkPolicy.Namespace, networkPolicy.Name),
					fmt.Sprintf("ovn-nbctl --timeout=15 --id=@acl create acl priority="+types.DefaultAllowPriority+" direction="+types.DirectionToLPort+" match=\"ip4 && tcp && tcp.dst==%d && outport == @a14195333570786048679\" action=allow-related log=false severity=info meter=acl-logging name=%s_%s_0 external-ids:l4Match=\"tcp && tcp.dst==%d\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Ingress_num=0 external-ids:policy_type=Ingress -- add port_group %s acls @acl", portNum, networkPolicy.Namespace, networkPolicy.Name, portNum, networkPolicy.Namespace, networkPolicy.Name, fakePgUUID),
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"tcp && tcp.dst==%d\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Egress_num=0 external-ids:policy_type=Egress", portNum, networkPolicy.Namespace, networkPolicy.Name),
					fmt.Sprintf("ovn-nbctl --timeout=15 --id=@acl create acl priority="+types.DefaultAllowPriority+" direction="+types.DirectionToLPort+" match=\"ip4 && tcp && tcp.dst==%d && inport == @a14195333570786048679\" action=allow-related log=false severity=info meter=acl-logging name=%s_%s_0 external-ids:l4Match=\"tcp && tcp.dst==%d\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Egress_num=0 external-ids:policy_type=Egress -- add port_group %s acls @acl", portNum, networkPolicy.Namespace, networkPolicy.Name, portNum, networkPolicy.Namespace, networkPolicy.Name, fakePgUUID),

					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"tcp && tcp.dst==%d\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Ingress_num=0 external-ids:policy_type=Ingress", portNum+1, networkPolicy2.Namespace, networkPolicy2.Name),
					fmt.Sprintf("ovn-nbctl --timeout=15 --id=@acl create acl priority="+types.DefaultAllowPriority+" direction="+types.DirectionToLPort+" match=\"ip4 && tcp && tcp.dst==%d && outport == @a14195334670297676890\" action=allow-related log=false severity=info meter=acl-logging name=%s_%s_0 external-ids:l4Match=\"tcp && tcp.dst==%d\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Ingress_num=0 external-ids:policy_type=Ingress -- add port_group %s acls @acl", portNum+1, networkPolicy2.Namespace, networkPolicy2.Name, portNum+1, networkPolicy2.Namespace, networkPolicy2.Name, fakePgUUID),
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"tcp && tcp.dst==%d\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Egress_num=0 external-ids:policy_type=Egress", portNum+1, networkPolicy2.Namespace, networkPolicy2.Name),
					fmt.Sprintf("ovn-nbctl --timeout=15 --id=@acl create acl priority="+types.DefaultAllowPriority+" direction="+types.DirectionToLPort+" match=\"ip4 && tcp && tcp.dst==%d && inport == @a14195334670297676890\" action=allow-related log=false severity=info meter=acl-logging name=%s_%s_0 external-ids:l4Match=\"tcp && tcp.dst==%d\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Egress_num=0 external-ids:policy_type=Egress -- add port_group %s acls @acl", portNum+1, networkPolicy2.Namespace, networkPolicy2.Name, portNum+1, networkPolicy2.Namespace, networkPolicy2.Name, fakePgUUID),
				})

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{namespace1},
					},
					&v1.PodList{
						Items: []v1.Pod{*nPod},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{*networkPolicy},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNetworkPolicy()

				ginkgo.By("Creating a network policy that applies to a pod")

				_, err := fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName1, []string{nPodTest.podIP})

				// assert that pod is in the default-deny portgroup

				// this helper function returns a function, because it's called behind
				// an
				getPGPorts := func(name string) func() ([]string, error) {
					return func() ([]string, error) {
						pg := &nbdb.PortGroup{Name: name}
						err := fakeOvn.nbClient.Get(pg)
						if err != nil {
							return nil, err
						}
						return pg.Ports, nil
					}
				}

				pgDefaultDenyName := defaultDenyPortGroup(namespace1.Name, "ingressDefaultDeny")
				gomega.Eventually(getPGPorts(pgDefaultDenyName)).Should(gomega.ConsistOf(fakeUUID))

				// assert that pod is in the NP's portgroup
				np1PG := hashedPortGroup(fmt.Sprintf("%s_%s", networkPolicy.Namespace, networkPolicy.Name))
				gomega.Eventually(getPGPorts(np1PG)).Should(gomega.ConsistOf(fakeUUID))
				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName1, []string{nPodTest.podIP})

				// Create a second NP
				ginkgo.By("Creating and deleting another policy that references that pod")

				_, err = fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Create(context.TODO(), networkPolicy2, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				// Check that portgroups look sane
				np2PG := hashedPortGroup(fmt.Sprintf("%s_%s", networkPolicy2.Namespace, networkPolicy2.Name))
				gomega.Eventually(getPGPorts(pgDefaultDenyName)).Should(gomega.ConsistOf(fakeUUID))
				gomega.Eventually(getPGPorts(np2PG)).Should(gomega.ConsistOf(fakeUUID))

				// Delete the second network policy
				err = fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy2.Namespace).Delete(context.TODO(), networkPolicy2.Name, metav1.DeleteOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				// Ensure the pod still has default deny
				gomega.Eventually(getPGPorts(pgDefaultDenyName)).Should(gomega.ConsistOf(fakeUUID))

				// Delete the first network policy
				ginkgo.By("Deleting that network policy")
				err = fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Delete(context.TODO(), networkPolicy.Name, metav1.DeleteOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				// Check that the default-deny portgroup is now deleted
				gomega.Eventually(func() error { _, err := getPGPorts(pgDefaultDenyName)(); return err }).Should(gomega.MatchError("object not found"))

				// fake exec checkup
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("reconciles a deleted namespace referenced by a networkpolicy with a local running pod", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := kNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace1.Name,
				)

				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, namespace2.Name)
				npTest.addLocalPodCmds(fExec, networkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNetworkPolicy()

				_, err := fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName1, []string{nPodTest.podIP})

				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, "")

				err = fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Delete(context.TODO(), namespace2.Name, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				fakeOvn.asf.EventuallyExpectNoAddressSet(namespaceName2)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("reconciles a deleted namespace referenced by a networkpolicy", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := kNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					})

				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, namespace2.Name)
				npTest.addDefaultDenyPGCmds(fExec, networkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)

				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				_, err := fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, "")

				err = fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Delete(context.TODO(), namespace2.Name, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("reconciles a deleted pod referenced by a networkpolicy in its own namespace", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := kNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace1.Name,
				)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, "")
				npTest.addLocalPodCmds(fExec, networkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNetworkPolicy()

				expectAddressSetsWithIP(fakeOvn, networkPolicy, nPodTest.podIP)
				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName1, []string{nPodTest.podIP})

				_, err := fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(nPodTest.namespace).Delete(context.TODO(), nPodTest.podName, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				eventuallyExpectEmptyAddressSets(fakeOvn, networkPolicy)
				fakeOvn.asf.EventuallyExpectEmptyAddressSet(namespaceName1)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("reconciles a deleted pod referenced by a networkpolicy in another namespace", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := kNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace2.Name,
				)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.namespace,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.namespace,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, "")
				npTest.addDefaultDenyPGCmds(fExec, networkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNetworkPolicy()

				fakeOvn.asf.ExpectEmptyAddressSet(namespaceName1)
				expectAddressSetsWithIP(fakeOvn, networkPolicy, nPodTest.podIP)
				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName2, []string{nPodTest.podIP})

				_, err := fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(nPodTest.namespace).Delete(context.TODO(), nPodTest.podName, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				// After deleting the pod all address sets should be empty
				eventuallyExpectEmptyAddressSets(fakeOvn, networkPolicy)
				fakeOvn.asf.EventuallyExpectEmptyAddressSet(namespaceName1)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
		ginkgo.It("reconciles an updated namespace label", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := kNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace2.Name,
				)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.namespace,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.namespace,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, "")
				npTest.addDefaultDenyPGCmds(fExec, networkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNetworkPolicy()

				fakeOvn.asf.ExpectEmptyAddressSet(namespaceName1)
				expectAddressSetsWithIP(fakeOvn, networkPolicy, nPodTest.podIP)
				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName2, []string{nPodTest.podIP})

				_, err := fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				namespace2.ObjectMeta.Labels = map[string]string{"labels": "test"}
				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Update(context.TODO(), &namespace2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				// After updating the namespace all address sets should be empty
				eventuallyExpectEmptyAddressSets(fakeOvn, networkPolicy)

				fakeOvn.asf.EventuallyExpectEmptyAddressSet(namespaceName1)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("reconciles a deleted networkpolicy", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := kNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace1.Name,
				)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, "")
				npTest.addLocalPodCmds(fExec, networkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNetworkPolicy()

				_, err := fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName1, []string{nPodTest.podIP})

				err = fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Delete(context.TODO(), networkPolicy.Name, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				eventuallyExpectNoAddressSets(fakeOvn, networkPolicy)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})
})

func asMatch(addressSets []string) string {
	hashedNames := make([]string, 0, len(addressSets))
	for _, as := range addressSets {
		v4HashedName, _ := addressset.MakeAddressSetHashNames(as)
		hashedNames = append(hashedNames, v4HashedName)
	}
	sort.Strings(hashedNames)
	var match string
	for i, n := range hashedNames {
		if i > 0 {
			match += ", "
		}
		match += fmt.Sprintf("$%s", n)
	}
	return match
}

func buildExpectedACLs(gp *gressPolicy, pgName string, as []string) []*nbdb.ACL {
	name := gp.policyNamespace + "_" + gp.policyName + "_" + strconv.Itoa(gp.idx)
	asMatch := asMatch(as)
	match := fmt.Sprintf("ip4.src == {%s} && outport == @%s", asMatch, pgName)
	gpDirection := string(knet.PolicyTypeIngress)
	return []*nbdb.ACL{
		{
			UUID:      name,
			Name:      []string{name},
			Match:     match,
			Priority:  1001,
			Direction: nbdb.ACLDirectionToLport,
			Action:    nbdb.ACLActionAllowRelated,
			Log:       true,
			Severity:  []string{nbdb.ACLSeverityInfo},
			Meter:     []string{"acl-logging"},
			ExternalIDs: map[string]string{
				"l4Match":            "None",
				"ipblock_cidr":       "false",
				"namespace":          gp.policyNamespace,
				"policy":             gp.policyName,
				gpDirection + "_num": fmt.Sprintf("%d", gp.idx),
				"policy_type":        gpDirection,
			},
		},
	}
}

var _ = ginkgo.Describe("OVN NetworkPolicy Low-Level Operations", func() {
	var (
		asFactory *addressset.FakeAddressSetFactory
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		asFactory = addressset.NewFakeAddressSetFactory()
		config.IPv4Mode = true
		config.IPv6Mode = false
	})

	ginkgo.It("computes match strings from address sets correctly", func() {
		const (
			pgName string = "pg-name"
		)

		policy := &knet.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				UID:       apimachinerytypes.UID("testing"),
				Name:      "policy",
				Namespace: "testing",
			},
		}

		gp := newGressPolicy(knet.PolicyTypeIngress, 0, policy.Namespace, policy.Name)
		err := gp.ensurePeerAddressSet(asFactory)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		asName := gp.peerAddressSet.GetName()

		one := "testing.policy.ingress.1"
		two := "testing.policy.ingress.2"
		three := "testing.policy.ingress.3"
		four := "testing.policy.ingress.4"
		five := "testing.policy.ingress.5"
		six := "testing.policy.ingress.6"

		gomega.Expect(gp.addNamespaceAddressSet(one)).To(gomega.BeTrue())
		expected := buildExpectedACLs(gp, pgName, []string{asName, one})
		actual := gp.buildLocalPodACLs(pgName, defaultACLLoggingSeverity)
		gomega.Expect(actual).To(gomega.Equal(expected))

		gomega.Expect(gp.addNamespaceAddressSet(two)).To(gomega.BeTrue())
		expected = buildExpectedACLs(gp, pgName, []string{asName, one, two})
		actual = gp.buildLocalPodACLs(pgName, defaultACLLoggingSeverity)
		gomega.Expect(actual).To(gomega.Equal(expected))

		// address sets should be alphabetized
		gomega.Expect(gp.addNamespaceAddressSet(three)).To(gomega.BeTrue())
		expected = buildExpectedACLs(gp, pgName, []string{asName, one, two, three})
		actual = gp.buildLocalPodACLs(pgName, defaultACLLoggingSeverity)
		gomega.Expect(actual).To(gomega.Equal(expected))

		// re-adding an existing set is a no-op
		gomega.Expect(gp.addNamespaceAddressSet(three)).To(gomega.BeFalse())

		gomega.Expect(gp.addNamespaceAddressSet(four)).To(gomega.BeTrue())
		expected = buildExpectedACLs(gp, pgName, []string{asName, one, two, three, four})
		actual = gp.buildLocalPodACLs(pgName, defaultACLLoggingSeverity)
		gomega.Expect(actual).To(gomega.Equal(expected))

		// now delete a set
		gomega.Expect(gp.delNamespaceAddressSet(one)).To(gomega.BeTrue())
		expected = buildExpectedACLs(gp, pgName, []string{asName, two, three, four})
		actual = gp.buildLocalPodACLs(pgName, defaultACLLoggingSeverity)
		gomega.Expect(actual).To(gomega.Equal(expected))

		// deleting again is a no-op
		gomega.Expect(gp.delNamespaceAddressSet(one)).To(gomega.BeFalse())

		// add and delete some more...
		gomega.Expect(gp.addNamespaceAddressSet(five)).To(gomega.BeTrue())
		expected = buildExpectedACLs(gp, pgName, []string{asName, two, three, four, five})
		actual = gp.buildLocalPodACLs(pgName, defaultACLLoggingSeverity)
		gomega.Expect(actual).To(gomega.Equal(expected))

		gomega.Expect(gp.delNamespaceAddressSet(three)).To(gomega.BeTrue())
		expected = buildExpectedACLs(gp, pgName, []string{asName, two, four, five})
		actual = gp.buildLocalPodACLs(pgName, defaultACLLoggingSeverity)
		gomega.Expect(actual).To(gomega.Equal(expected))

		// deleting again is no-op
		gomega.Expect(gp.delNamespaceAddressSet(one)).To(gomega.BeFalse())

		gomega.Expect(gp.addNamespaceAddressSet(six)).To(gomega.BeTrue())
		expected = buildExpectedACLs(gp, pgName, []string{asName, two, four, five, six})
		actual = gp.buildLocalPodACLs(pgName, defaultACLLoggingSeverity)
		gomega.Expect(actual).To(gomega.Equal(expected))

		gomega.Expect(gp.delNamespaceAddressSet(two)).To(gomega.BeTrue())
		expected = buildExpectedACLs(gp, pgName, []string{asName, four, five, six})
		actual = gp.buildLocalPodACLs(pgName, defaultACLLoggingSeverity)
		gomega.Expect(actual).To(gomega.Equal(expected))

		gomega.Expect(gp.delNamespaceAddressSet(five)).To(gomega.BeTrue())
		expected = buildExpectedACLs(gp, pgName, []string{asName, four, six})
		actual = gp.buildLocalPodACLs(pgName, defaultACLLoggingSeverity)
		gomega.Expect(actual).To(gomega.Equal(expected))

		gomega.Expect(gp.delNamespaceAddressSet(six)).To(gomega.BeTrue())
		expected = buildExpectedACLs(gp, pgName, []string{asName, four})
		actual = gp.buildLocalPodACLs(pgName, defaultACLLoggingSeverity)
		gomega.Expect(actual).To(gomega.Equal(expected))

		gomega.Expect(gp.delNamespaceAddressSet(four)).To(gomega.BeTrue())
		expected = buildExpectedACLs(gp, pgName, []string{asName})
		actual = gp.buildLocalPodACLs(pgName, defaultACLLoggingSeverity)
		gomega.Expect(actual).To(gomega.Equal(expected))

		// deleting again is no-op
		gomega.Expect(gp.delNamespaceAddressSet(four)).To(gomega.BeFalse())
	})
})
