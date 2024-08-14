package networkqos

import (
	"fmt"
	"strconv"

	"k8s.io/klog/v2"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	libovsdb "github.com/ovn-org/libovsdb/ovsdb"

	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

func (c *Controller) reconcileNetworkQoS(qosState *networkQoSState) ([]*nbdb.QoS, []libovsdb.Operation, error) {
	allQoSes := []*nbdb.QoS{}
	newQoSes := []*nbdb.QoS{}
	ops := []libovsdb.Operation{}
	for index, rule := range qosState.EgressRules {
		dbIDs := qosState.getDbObjectIDs(c.controllerName, index)
		predicate := libovsdbops.GetPredicate[*nbdb.QoS](dbIDs, func(item *nbdb.QoS) bool {
			return item.ExternalIDs[libovsdbops.OwnerControllerKey.String()] == c.controllerName &&
				item.ExternalIDs[libovsdbops.ObjectNameKey.String()] == qosState.getObjectNameKey() &&
				item.ExternalIDs[libovsdbops.RuleIndex.String()] == strconv.Itoa(index)
		})
		qoses, err := libovsdbops.FindQoSesWithPredicate(c.nbClient, predicate)
		if err != nil && err != libovsdbclient.ErrNotFound {
			return nil, nil, fmt.Errorf("failed to lookup qos for %s/%s, index %d: %w", qosState.namespace, qosState.name, index, err)
		}
		if len(qoses) > 1 {
			return nil, nil, fmt.Errorf("found multiple QoSes for %s/%s at rule index %d", qosState.namespace, qosState.name, index)
		}
		if len(qoses) == 1 {
			allQoSes = append(allQoSes, qoses[0])
			continue
		}
		qos := &nbdb.QoS{
			Action:      map[string]int{},
			Bandwidth:   map[string]int{},
			Direction:   nbdb.QoSDirectionToLport,
			ExternalIDs: dbIDs.GetExternalIDs(),
			Match:       generateNetworkQoSMatch(qosState, rule),
			Priority:    rule.Priority,
		}
		if rule.Dscp >= 0 {
			qos.Action[nbdb.QoSActionDSCP] = rule.Dscp
		}
		if rule.Rate != nil && *rule.Rate > 0 {
			qos.Bandwidth[nbdb.QoSBandwidthRate] = *rule.Rate
		}
		if rule.Burst != nil && *rule.Burst > 0 {
			qos.Bandwidth[nbdb.QoSBandwidthBurst] = *rule.Burst
		}
		newQoSes = append(newQoSes, qos)
	}
	ops, err := libovsdbops.CreateOrUpdateQoSesOps(c.nbClient, ops, newQoSes...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create QoS operations for %s/%s: %w", qosState.namespace, qosState.name, err)
	}
	allQoSes = append(allQoSes, newQoSes...)
	return allQoSes, ops, nil
}

func (c *Controller) addQoSToLogicalSwitch(qosState *networkQoSState, switchName string) error {
	qoses, ops, err := c.reconcileNetworkQoS(qosState)
	if err != nil {
		return err
	}
	ops, err = libovsdbops.AddQoSesToLogicalSwitchOps(c.nbClient, ops, switchName, qoses...)
	if err != nil {
		return fmt.Errorf("failed to create operations to add QoS to switch %s: %w", switchName, err)
	}
	if _, err := libovsdbops.TransactAndCheck(c.nbClient, ops); err != nil {
		return fmt.Errorf("failed to execute ops to add QoSes to switch %s, err: %w", switchName, err)
	}
	return nil
}

func (c *Controller) removeQoSFromLogicalSwitches(qosState *networkQoSState, switchNames []string) error {
	qoses, err := libovsdbops.FindQoSesWithPredicate(c.nbClient, func(qos *nbdb.QoS) bool {
		return qos.ExternalIDs[libovsdbops.OwnerControllerKey.String()] == c.controllerName &&
			qos.ExternalIDs[libovsdbops.ObjectNameKey.String()] == qosState.getObjectNameKey()
	})
	if err != nil {
		return fmt.Errorf("failed to look up QoSes for %s/%s: %v", qosState.namespace, qosState.name, err)
	}
	unbindQoSOps := []libovsdb.Operation{}
	// remove qos rules from logical switches
	for _, lsName := range switchNames {
		ops, err := libovsdbops.RemoveQoSesFromLogicalSwitchOps(c.nbClient, nil, lsName, qoses...)
		if err != nil {
			return fmt.Errorf("failed to get ops to remove QoSes from switches %s for NetworkQoS %s/%s: %w", lsName, qosState.namespace, qosState.name, err)
		}
		unbindQoSOps = append(unbindQoSOps, ops...)
	}
	if _, err := libovsdbops.TransactAndCheck(c.nbClient, unbindQoSOps); err != nil {
		return fmt.Errorf("failed to execute ops to remove QoSes from logical switches, err: %w", err)
	}
	return nil
}

func (c *Controller) updateAddressSet(addrset addressset.AddressSet, newAddresses []string) error {
	ipv4Addresses, ipv6Addresses := addrset.GetAddresses()
	staleAddresses := []string{}
	diffAddresses := []string{}
	for _, address := range ipv4Addresses {
		if !util.SliceHasStringItem(newAddresses, address) {
			staleAddresses = append(staleAddresses, address)
		}
	}
	for _, address := range ipv6Addresses {
		if !util.SliceHasStringItem(newAddresses, address) {
			staleAddresses = append(staleAddresses, address)
		}
	}
	for _, address := range newAddresses {
		if !util.SliceHasStringItem(ipv4Addresses, address) && !util.SliceHasStringItem(ipv6Addresses, address) {
			diffAddresses = append(diffAddresses, address)
		}
	}
	allOps, err := addrset.DeleteAddressesReturnOps(staleAddresses)
	if err != nil {
		return fmt.Errorf("failed to create address deletion operations for %s: %w", addrset.GetName(), err)
	}
	ops, err := addrset.AddAddressesReturnOps(diffAddresses)
	if err != nil {
		return fmt.Errorf("failed to create address addition operations for %s: %w", addrset.GetName(), err)
	}
	allOps = append(allOps, ops...)
	if _, err := libovsdbops.TransactAndCheck(c.nbClient, allOps); err != nil {
		return fmt.Errorf("failed to update addresses for set %s: %w", addrset.GetName(), err)
	}
	return nil
}

func (c *Controller) updateSourceAddresses(nqosState *networkQoSState) error {
	if isNamespaceAddressSet(nqosState.SrcAddrSet) {
		// ignore namespace address set
		return nil
	}
	newAddresses, err := c.getSourceIPs(nqosState)
	if err != nil {
		return err
	}
	return c.updateAddressSet(nqosState.SrcAddrSet, newAddresses)
}

func (c *Controller) updateDestAddresses(nqosState *networkQoSState) error {
	for _, rule := range nqosState.EgressRules {
		for _, dest := range rule.Classifier.Destinations {
			if dest.DestAddrSet == nil {
				continue
			}
			newAddresses, err := c.getDestIPs(nqosState, dest)
			if err != nil {
				return err
			}
			if err = c.updateAddressSet(dest.DestAddrSet, newAddresses); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Controller) deleteStaleQoSes(qosState *networkQoSState) error {
	existingQoSes, err := libovsdbops.FindQoSesWithPredicate(c.nbClient, func(qos *nbdb.QoS) bool {
		return qos.ExternalIDs[libovsdbops.OwnerControllerKey.String()] == c.controllerName &&
			qos.ExternalIDs[libovsdbops.ObjectNameKey.String()] == qosState.getObjectNameKey()
	})
	if err != nil {
		return fmt.Errorf("failed to look up existing QoSes for %s/%s: %v", qosState.namespace, qosState.name, err)
	}
	staleAddressSetNames, err := c.findStaleAddressSets(qosState)
	if err != nil {
		return fmt.Errorf("failed to look up stale address sets for %s/%s: %w", qosState.namespace, qosState.name, err)
	}
	staleQoSes := []*nbdb.QoS{}
	switchQoSMap := map[string][]*nbdb.QoS{}
	totalNumOfRules := len(qosState.EgressRules)
	for _, qos := range existingQoSes {
		index := qos.ExternalIDs[libovsdbops.RuleIndex.String()]
		numIndex, convError := strconv.Atoi(index)
		if index != "" && convError == nil && numIndex < totalNumOfRules {
			// rule index is valid and within range
			continue
		}
		// rule index is invalid or out of range
		staleQoSes = append(staleQoSes, qos)
		switches, err := libovsdbops.FindLogicalSwitchesWithPredicate(c.nbClient, func(ls *nbdb.LogicalSwitch) bool {
			return util.SliceHasStringItem(ls.QOSRules, qos.UUID)
		})
		if err != nil {
			if err != libovsdbclient.ErrNotFound {
				return fmt.Errorf("failed to look up logical switches by qos: %w", err)
			}
			continue
		}
		// get switches that reference to the stale qoses
		for _, ls := range switches {
			qosList := switchQoSMap[ls.UUID]
			if qosList == nil {
				qosList = []*nbdb.QoS{}
			}
			qosList = append(qosList, qos)
			switchQoSMap[ls.Name] = qosList
		}
		staleAddressSetNames = append(staleAddressSetNames, parseAddressSetNames(qos.Match)...)
	}
	// remove stale address sets
	allOps := []libovsdb.Operation{}
	var addrsetOps []libovsdb.Operation
	addrsetOps, err = libovsdbops.DeleteAddressSetsWithPredicateOps(c.nbClient, addrsetOps, func(item *nbdb.AddressSet) bool {
		return item.ExternalIDs[libovsdbops.OwnerControllerKey.String()] == c.controllerName &&
			item.ExternalIDs[libovsdbops.ObjectNameKey.String()] == qosState.getObjectNameKey() &&
			util.SliceHasStringItem(staleAddressSetNames, item.Name)
	})
	if err != nil {
		return fmt.Errorf("failed to get ops to delete stale address sets for NetworkQoS %s/%s: %w", qosState.namespace, qosState.name, err)
	}
	allOps = append(allOps, addrsetOps...)
	// remove stale qos rules from logical switches
	for lsName, qoses := range switchQoSMap {
		var switchOps []libovsdb.Operation
		switchOps, err = libovsdbops.RemoveQoSesFromLogicalSwitchOps(c.nbClient, switchOps, lsName, qoses...)
		if err != nil {
			return fmt.Errorf("failed to get ops to remove stale QoSes from switches %s for NetworkQoS %s/%s: %w", lsName, qosState.namespace, qosState.name, err)
		}
		allOps = append(allOps, switchOps...)
	}
	// delete stale qos
	var qosOps []libovsdb.Operation
	qosOps, err = libovsdbops.DeleteQoSesOps(c.nbClient, qosOps, staleQoSes...)
	if err != nil {
		return fmt.Errorf("failed to get ops to delete stale QoSes for NetworkQoS %s/%s: %w", qosState.namespace, qosState.name, err)
	}
	allOps = append(allOps, qosOps...)

	// commit allOps
	if _, err := libovsdbops.TransactAndCheck(c.nbClient, allOps); err != nil {
		return fmt.Errorf("failed to execute ops to clean up stale QoSes, err: %w", err)
	}
	return nil
}

func (c *Controller) deleteQoSes(qosState *networkQoSState) error {
	qoses, err := libovsdbops.FindQoSesWithPredicate(c.nbClient, func(qos *nbdb.QoS) bool {
		return qos.ExternalIDs[libovsdbops.OwnerControllerKey.String()] == c.controllerName &&
			qos.ExternalIDs[libovsdbops.ObjectNameKey.String()] == qosState.getObjectNameKey()
	})
	if err != nil {
		return fmt.Errorf("failed to look up QoSes for %s/%s: %v", qosState.namespace, qosState.name, err)
	}
	switchQoSMap := map[string][]*nbdb.QoS{}
	for _, qos := range qoses {
		switches, err := libovsdbops.FindLogicalSwitchesWithPredicate(c.nbClient, func(ls *nbdb.LogicalSwitch) bool {
			return util.SliceHasStringItem(ls.QOSRules, qos.UUID)
		})
		if err != nil {
			if err != libovsdbclient.ErrNotFound {
				return fmt.Errorf("failed to look up logical switches by qos: %w", err)
			}
			continue
		}
		// get switches that reference to the stale qoses
		for _, ls := range switches {
			qosList := switchQoSMap[ls.Name]
			if qosList == nil {
				qosList = []*nbdb.QoS{}
			}
			qosList = append(qosList, qos)
			switchQoSMap[ls.Name] = qosList
		}
	}
	unbindQoSOps := []libovsdb.Operation{}
	// remove qos rules from logical switches
	for lsName, qoses := range switchQoSMap {
		ops, err := libovsdbops.RemoveQoSesFromLogicalSwitchOps(c.nbClient, nil, lsName, qoses...)
		if err != nil {
			return fmt.Errorf("failed to get ops to remove QoSes from switches %s for NetworkQoS %s/%s: %w", lsName, qosState.namespace, qosState.name, err)
		}
		unbindQoSOps = append(unbindQoSOps, ops...)
	}
	if _, err := libovsdbops.TransactAndCheck(c.nbClient, unbindQoSOps); err != nil {
		return fmt.Errorf("failed to execute ops to remove QoSes from logical switches, err: %w", err)
	}
	// delete qos
	delQoSOps, err := libovsdbops.DeleteQoSesOps(c.nbClient, nil, qoses...)
	if err != nil {
		return fmt.Errorf("failed to get ops to delete QoSes for NetworkQoS %s/%s: %w", qosState.namespace, qosState.name, err)
	}
	if _, err := libovsdbops.TransactAndCheck(c.nbClient, delQoSOps); err != nil {
		return fmt.Errorf("failed to execute ops to delete QoSes, err: %w", err)
	}
	// remove address sets
	delAddrSetOps, err := libovsdbops.DeleteAddressSetsWithPredicateOps(c.nbClient, nil, func(item *nbdb.AddressSet) bool {
		return item.ExternalIDs[libovsdbops.OwnerControllerKey.String()] == c.controllerName &&
			item.ExternalIDs[libovsdbops.ObjectNameKey.String()] == qosState.getObjectNameKey()
	})
	if err != nil {
		return fmt.Errorf("failed to get ops to delete address sets for NetworkQoS %s/%s: %w", qosState.namespace, qosState.name, err)
	}
	if _, err := libovsdbops.TransactAndCheck(c.nbClient, delAddrSetOps); err != nil {
		return fmt.Errorf("failed to execute ops to delete address sets, err: %w", err)
	}
	return nil
}

func (c *Controller) findStaleAddressSets(qosState *networkQoSState) ([]string, error) {
	staleAddressSets := []string{}
	addrsets, err := libovsdbops.FindAddressSetsWithPredicate(c.nbClient, func(item *nbdb.AddressSet) bool {
		return item.ExternalIDs[libovsdbops.OwnerControllerKey.String()] == c.controllerName &&
			item.ExternalIDs[libovsdbops.ObjectNameKey.String()] == qosState.getObjectNameKey() &&
			item.ExternalIDs[libovsdbops.RuleIndex.String()] != "src"
	})
	if err != nil {
		return nil, fmt.Errorf("failed to look up address sets: %w", err)
	}
	for _, addrset := range addrsets {
		ruleIndexStr := addrset.ExternalIDs[libovsdbops.RuleIndex.String()]
		ruleIndex, convErr := strconv.Atoi(ruleIndexStr)
		if convErr != nil {
			klog.Errorf("Unable to convert address set's rule-index %s to number: %v", ruleIndexStr, convErr)
			staleAddressSets = append(staleAddressSets, addrset.GetName())
			continue
		}
		destIndexStr := addrset.ExternalIDs[libovsdbops.IpBlockIndexKey.String()]
		destIndex, convErr := strconv.Atoi(destIndexStr)
		if convErr != nil {
			klog.Errorf("Unable to convert address set's ip-block-index %s to number: %v", destIndexStr, convErr)
			staleAddressSets = append(staleAddressSets, addrset.GetName())
			continue
		}
		if ruleIndex >= len(qosState.EgressRules) {
			klog.Errorf("address set's rule-index %d exceeds total number of rules %d", ruleIndex, len(qosState.EgressRules))
			staleAddressSets = append(staleAddressSets, addrset.GetName())
			continue
		}
		rule := qosState.EgressRules[ruleIndex]
		if rule.Classifier != nil && destIndex >= len(rule.Classifier.Destinations) {
			klog.Errorf("address set's ip-block-index %d exceeds total number %d", destIndex, len(rule.Classifier.Destinations))
			staleAddressSets = append(staleAddressSets, addrset.GetName())
		}
	}
	return staleAddressSets, nil
}
