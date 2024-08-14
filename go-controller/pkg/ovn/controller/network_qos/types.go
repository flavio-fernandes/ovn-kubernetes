package networkqos

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	v1 "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
)

// networkQoSState is the cache that keeps the state of a single
// network qos in the cluster with namespace+name being unique
type networkQoSState struct {
	sync.RWMutex
	// name of the network qos
	name      string
	namespace string

	networkAttachmentName string

	SrcAddrSet  addressset.AddressSet
	Pods        sync.Map // pods name -> ips in the srcAddrSet
	NodeRefs    sync.Map // node name -> number of source pods
	PodSelector labels.Selector

	// egressRules stores the objects needed to track .Spec.Egress changes
	EgressRules []*GressRule
}

func (nqosState *networkQoSState) getObjectNameKey() string {
	return joinMetaNamespaceAndName(nqosState.namespace, nqosState.name, ":")
}

func (nqosState *networkQoSState) getDbObjectIDs(controller string, ruleIndex int) *libovsdbops.DbObjectIDs {
	return libovsdbops.NewDbObjectIDs(libovsdbops.NetworkQoS, controller, map[libovsdbops.ExternalIDKey]string{
		libovsdbops.ObjectNameKey: nqosState.getObjectNameKey(),
		libovsdbops.RuleIndex:     fmt.Sprintf("%d", ruleIndex),
	})
}

func (nqosState *networkQoSState) initAddressSets(addressSetFactory addressset.AddressSetFactory, controllerName string) error {
	var err error
	// init source address set
	if nqosState.PodSelector == nil {
		nqosState.SrcAddrSet, err = getNamespaceAddressSet(addressSetFactory, controllerName, nqosState.namespace)
	} else {
		nqosState.SrcAddrSet, err = ensureAddressSet(addressSetFactory, GetNetworkQoSAddrSetDbIDs(nqosState.namespace, nqosState.name, "src", "0", controllerName))
	}
	if err != nil {
		return fmt.Errorf("failed to ensure source address set for %s/%s: %w", nqosState.namespace, nqosState.name, err)
	}

	// ensure destination address sets
	for ruleIndex, rule := range nqosState.EgressRules {
		for destIndex, dest := range rule.Classifier.Destinations {
			if dest.NamespaceSelector == nil && dest.PodSelector == nil {
				continue
			}
			dbObjectIDs := libovsdbops.NewDbObjectIDs(libovsdbops.AddressSetNetworkQoS, controllerName, map[libovsdbops.ExternalIDKey]string{
				libovsdbops.ObjectNameKey:   nqosState.getObjectNameKey(),
				libovsdbops.RuleIndex:       fmt.Sprintf("%d", ruleIndex),
				libovsdbops.IpBlockIndexKey: fmt.Sprintf("%d", destIndex),
			})
			dest.DestAddrSet, err = ensureAddressSet(addressSetFactory, dbObjectIDs)
			if err != nil {
				return fmt.Errorf("failed to ensure destination address set for %s/%s: %w", nqosState.namespace, nqosState.name, err)
			}
		}
	}
	return nil
}

func (nqosState *networkQoSState) isEligibleSource(pod *v1.Pod) bool {
	if nqosState.PodSelector == nil {
		// no op, address will be added to namespace address set
		return false
	}
	return nqosState.PodSelector.Matches(labels.Set(pod.Labels))
}

func (nqosState *networkQoSState) hasSource(pod *v1.Pod) bool {
	_, loaded := nqosState.Pods.Load(joinMetaNamespaceAndName(pod.Namespace, pod.Name))
	return loaded
}

func (nqosState *networkQoSState) addPodToSource(ctrl *Controller, pod *v1.Pod, addresses []string) error {
	if err := nqosState.SrcAddrSet.AddAddresses(addresses); err != nil {
		return fmt.Errorf("failed to add addresses {%s} to address set %s for NetworkQoS %s/%s: %v", strings.Join(addresses, ","), nqosState.SrcAddrSet.GetName(), nqosState.namespace, nqosState.name, err)
	}
	fullPodName := joinMetaNamespaceAndName(pod.Namespace, pod.Name)
	nqosState.Pods.Store(fullPodName, addresses)

	// add qos to switch
	switchName := ""
	if pod.Spec.NodeName != "" {
		node, err := ctrl.nqosNodeLister.Get(pod.Spec.NodeName)
		if err != nil {
			if errors.IsNotFound(err) {
				klog.Errorf("Node %s not found, not retrying", pod.Spec.NodeName)
				return nil
			}
			return fmt.Errorf("failed to look up node %s: %v", pod.Spec.NodeName, err)
		}
		if ctrl.isNodeInLocalZone(node) {
			switchName = ctrl.GetNetworkScopedSwitchName(pod.Spec.NodeName)
		}
	}
	// add qos rule to logical switch
	if switchName != "" {
		if err := ctrl.addQoSToLogicalSwitch(nqosState, switchName); err != nil {
			return err
		}
	}
	podList := []string{}
	val, loaded := nqosState.NodeRefs.Load(pod.Spec.NodeName)
	if loaded {
		podList = val.([]string)
	}
	podList = append(podList, fullPodName)
	nqosState.NodeRefs.Store(pod.Spec.NodeName, podList)
	return nil
}

func (nqosState *networkQoSState) removePodFromSource(ctrl *Controller, fullPodName string) error {
	val, ok := nqosState.Pods.Load(fullPodName)
	if !ok {
		return nil
	}
	// remove pod from non-namespace source address set
	addresses := val.([]string)
	if err := nqosState.SrcAddrSet.DeleteAddresses(addresses); err != nil {
		return fmt.Errorf("failed to delete addresses (%s) from address set %s: %v", strings.Join(addresses, ","), nqosState.SrcAddrSet.GetName(), err)
	}
	nqosState.Pods.Delete(fullPodName)

	// update node ref
	zeroQoSNodes := []string{}
	nqosState.NodeRefs.Range(func(key, val any) bool {
		nodeName := key.(string)
		podList := val.([]string)
		podList = slices.DeleteFunc(podList, func(s string) bool {
			return s == fullPodName
		})
		nqosState.NodeRefs.Store(nodeName, podList)
		if len(podList) == 0 {
			zeroQoSNodes = append(zeroQoSNodes, nodeName)
		}
		return true
	})
	if err := ctrl.removeQoSFromLogicalSwitches(nqosState, zeroQoSNodes); err != nil {
		return err
	}
	for _, node := range zeroQoSNodes {
		nqosState.NodeRefs.Delete(node)
	}
	return nil
}

type GressRule struct {
	Priority   int
	Dscp       int
	Classifier *Classifier

	// bandwitdh
	Rate  *int
	Burst *int
}

type protocol string

const (
	protoTcp  protocol = "tcp"
	protoUdp  protocol = "udp"
	protoSctp protocol = "sctp"
)

func (p protocol) IsValid() bool {
	switch p.String() {
	case "tcp", "udp", "sctp":
		return true
	default:
		return false
	}
}

func (p protocol) String() string {
	return strings.ToLower(string(p))
}

type trafficDirection string

const (
	trafficDirSource trafficDirection = "src"
	trafficDirDest   trafficDirection = "dst"
)

type Classifier struct {
	Destinations []*Destination

	// port
	Protocol protocol
	Port     *int
}

func (c *Classifier) MatchString() string {
	if c == nil {
		return ""
	}
	destMatchStrings := []string{}
	for _, dest := range c.Destinations {
		addrSetMatch := addressSetToMatchString(dest.DestAddrSet, trafficDirDest)
		ipBlockMatch := ""
		if dest.IpBlock != nil && dest.IpBlock.CIDR != "" {
			ipVersion := "ip4"
			if utilnet.IsIPv6CIDRString(dest.IpBlock.CIDR) {
				ipVersion = "ip6"
			}
			if len(dest.IpBlock.Except) == 0 {
				ipBlockMatch = fmt.Sprintf("%s.%s == %s", ipVersion, trafficDirDest, dest.IpBlock.CIDR)
			} else {
				ipBlockMatch = fmt.Sprintf("(%s.%s == %s && %s.%s != {%s})", ipVersion, trafficDirDest, dest.IpBlock.CIDR, ipVersion, trafficDirDest, strings.Join(dest.IpBlock.Except, ", "))
			}
		}
		match := ""
		if addrSetMatch != "" && ipBlockMatch != "" {
			match = addrSetMatch + " || " + ipBlockMatch
		} else if addrSetMatch != "" {
			match = addrSetMatch
		} else if ipBlockMatch != "" {
			match = ipBlockMatch
		} else {
			continue
		}
		destMatchStrings = append(destMatchStrings, match)
	}

	output := ""
	if len(destMatchStrings) == 1 {
		output = destMatchStrings[0]
	} else {
		for index, str := range destMatchStrings {
			output = output + fmt.Sprintf("(%s)", str)
			if index < len(destMatchStrings)-1 {
				output = output + " || "
			}
		}
	}
	if strings.Contains(output, "||") {
		output = fmt.Sprintf("(%s)", output)
	}
	if c.Protocol != "" {
		if c.Port != nil && *c.Port > 0 {
			match := fmt.Sprintf("%s && %s.dst == %d", c.Protocol.String(), c.Protocol.String(), *c.Port)
			if output != "" {
				output = fmt.Sprintf("%s && %s", output, match)
			} else {
				output = match
			}
		} else {
			if output != "" {
				output = fmt.Sprintf("%s && %s", output, c.Protocol.String())
			} else {
				output = c.Protocol.String()
			}
		}
	}
	return output
}

type Destination struct {
	IpBlock *knet.IPBlock

	DestAddrSet       addressset.AddressSet
	PodSelector       labels.Selector
	Pods              sync.Map // pods name -> ips in the destAddrSet
	NamespaceSelector labels.Selector
	Namespaces        sync.Map // namespace name -> bool
}

func (dest *Destination) matchNamespace(podNs *v1.Namespace, qosNamespace string) bool {
	if dest.NamespaceSelector == nil {
		return podNs.Name == qosNamespace
	}
	return dest.NamespaceSelector.Matches(labels.Set(podNs.Labels))
}

func (dest *Destination) hasNamespace(namespace string) bool {
	_, loaded := dest.Namespaces.Load(namespace)
	return loaded
}

func (dest *Destination) matchPod(pod *v1.Pod) bool {
	if dest.PodSelector == nil {
		return false
	}
	return dest.PodSelector.Matches(labels.Set(pod.Labels))
}

func (dest *Destination) addPod(fullPodName string, addresses []string) error {
	if err := dest.DestAddrSet.AddAddresses(addresses); err != nil {
		return err
	}
	// add pod to map
	dest.Pods.Store(fullPodName, addresses)
	return nil
}

func (dest *Destination) removePod(fullPodName string) error {
	val, ok := dest.Pods.Load(fullPodName)
	if !ok {
		return nil
	}
	addresses := val.([]string)
	if err := dest.DestAddrSet.DeleteAddresses(addresses); err != nil {
		return err
	}
	dest.Pods.Delete(fullPodName)
	return nil
}

func (dest *Destination) removePodsInNamespace(namespace string) error {
	var err error
	// check for pods in the namespace being cleared
	dest.Pods.Range(func(key, value any) bool {
		fullPodName := key.(string)
		nameParts := strings.Split(fullPodName, "/")
		if nameParts[0] != namespace {
			// pod's namespace doesn't match
			return true
		}
		err = dest.removePod(fullPodName)
		return err == nil
	})
	dest.Namespaces.Delete(namespace)
	return err
}

func (dest *Destination) addPodsInNamespace(ctrl *Controller, networkAttachmentName, namespace string) error {
	podSelector := labels.Everything()
	if dest.PodSelector != nil {
		podSelector = dest.PodSelector
	}
	pods, err := ctrl.nqosPodLister.Pods(namespace).List(podSelector)
	if err != nil {
		if errors.IsNotFound(err) || len(pods) == 0 {
			return nil
		}
		return fmt.Errorf("failed to look up pods in ns %s: %v", namespace, err)
	}
	klog.V(5).Infof("Got %d pods in namespace %s by selector %s", len(pods), namespace, podSelector.String())
	for _, pod := range pods {
		podAddresses, err := getPodAddresses(pod, networkAttachmentName)
		if err != nil {
			return fmt.Errorf("failed to parse IPs for pod %s/%s: %v", pod.Namespace, pod.Name, err)
		}
		if err := dest.addPod(joinMetaNamespaceAndName(pod.Namespace, pod.Name), podAddresses); err != nil {
			return fmt.Errorf("failed to add addresses {%s} to address set %s: %v", strings.Join(podAddresses, ","), dest.DestAddrSet.GetName(), err)
		}
	}
	// cache mathing namespace
	dest.Namespaces.Store(namespace, true)
	return nil
}
