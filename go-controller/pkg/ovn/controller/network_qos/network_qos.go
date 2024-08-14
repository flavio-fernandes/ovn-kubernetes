package networkqos

import (
	"context"
	"fmt"
	"sync"
	"time"

	// v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	// "k8s.io/apimachinery/pkg/util/sets"

	// libovsdbclient "github.com/ovn-org/libovsdb/client"
	// "github.com/ovn-org/libovsdb/ovsdb"
	// libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	// libovsdbutil "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/util"
	// "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	// "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	// "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	networkqosapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/networkqos/v1"
	nqosapiapply "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/networkqos/v1/apis/applyconfiguration/networkqos/v1"
)

func (c *Controller) processNextNQOSWorkItem(wg *sync.WaitGroup) bool {
	wg.Add(1)
	defer wg.Done()
	nqosKey, quit := c.nqosQueue.Get()
	if quit {
		return false
	}
	defer c.nqosQueue.Done(nqosKey)

	err := c.syncNetworkQoS(nqosKey.(string))
	if err == nil {
		c.nqosQueue.Forget(nqosKey)
		return true
	}
	utilruntime.HandleError(fmt.Errorf("%v failed with: %v", nqosKey, err))

	if c.nqosQueue.NumRequeues(nqosKey) < maxRetries {
		c.nqosQueue.AddRateLimited(nqosKey)
		return true
	}

	c.nqosQueue.Forget(nqosKey)
	return true
}

// syncNetworkQoS decides the main logic everytime
// we dequeue a key from the nqosQueue cache
func (c *Controller) syncNetworkQoS(key string) error {
	// TODO(ffernandes): A global lock is currently used from syncNetworkQoS, syncNetworkQoSPod,
	// syncNetworkQoSNamespace and syncNetworkQoSNode. Planning to do perf/scale runs first
	// and will remove this TODO if there are no concerns with the lock.
	c.Lock()
	defer c.Unlock()
	startTime := time.Now()
	nqosNamespace, nqosName, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	klog.V(5).Infof("Processing sync for Network QoS %s", nqosName)

	defer func() {
		klog.V(5).Infof("Finished syncing Network QoS %s : %v", nqosName, time.Since(startTime))
	}()

	nqos, err := c.nqosLister.NetworkQoSes(nqosNamespace).Get(nqosName)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if nqos == nil {
		// it was deleted; let's clear up all the related resources to that
		err = c.clearNetworkQos(nqosNamespace, nqosName)
		if err != nil {
			return err
		}
		return nil
	}
	// at this stage the NQOS exists in the cluster
	err = c.ensureNetworkQos(nqos)
	if err != nil {
		// we can ignore the error if status update doesn't succeed; best effort
		_ = c.updateNQOSStatusToNotReady(nqos.Namespace, nqos.Name, err.Error())
		return err
	}
	// we can ignore the error if status update doesn't succeed; best effort
	_ = c.updateNQOSStatusToReady(nqos.Namespace, nqos.Name)
	return nil
}

// ensureNetworkQos will handle the main reconcile logic for any given nqos's
// add/update that might be triggered either due to NQOS changes or the corresponding
// matching pod or namespace changes.
func (c *Controller) ensureNetworkQos(nqos *networkqosapi.NetworkQoS) error {
	desiredNQOSState := &networkQoSState{
		name:                  nqos.Name,
		namespace:             nqos.Namespace,
		networkAttachmentName: nqos.Spec.NetworkAttachmentName,
	}
	if desiredNQOSState.networkAttachmentName == "" {
		desiredNQOSState.networkAttachmentName = c.GetNetworkName()
	}

	if len(nqos.Spec.PodSelector.MatchLabels) > 0 || len(nqos.Spec.PodSelector.MatchExpressions) > 0 {
		if podSelector, err := metav1.LabelSelectorAsSelector(&nqos.Spec.PodSelector); err != nil {
			return fmt.Errorf("failed to parse source pod selector of NetworkQoS %s/%s: %w", nqos.Namespace, nqos.Name, err)
		} else {
			desiredNQOSState.PodSelector = podSelector
		}
	}

	// set EgressRules to desiredNQOSState
	rules := []*GressRule{}
	for _, ruleSpec := range nqos.Spec.Egress {
		bwRate := int(ruleSpec.Bandwidth.Rate)
		bwBurst := int(ruleSpec.Bandwidth.Burst)
		ruleState := &GressRule{
			Priority: ruleSpec.Priority,
			Dscp:     ruleSpec.DSCP,
			Rate:     &bwRate,
			Burst:    &bwBurst,
		}
		destStates := []*Destination{}
		for _, destSpec := range ruleSpec.Classifier.To {
			destState := &Destination{}
			destState.IpBlock = destSpec.IPBlock.DeepCopy()
			if destSpec.NamespaceSelector != nil && (len(destSpec.NamespaceSelector.MatchLabels) > 0 || len(destSpec.NamespaceSelector.MatchExpressions) > 0) {
				if selector, err := metav1.LabelSelectorAsSelector(destSpec.NamespaceSelector); err != nil {
					return fmt.Errorf("failed to parse namespace selector: %w", err)
				} else {
					destState.NamespaceSelector = selector
				}
			}
			if destSpec.PodSelector != nil && (len(destSpec.PodSelector.MatchLabels) > 0 || len(destSpec.PodSelector.MatchExpressions) > 0) {
				if selector, err := metav1.LabelSelectorAsSelector(destSpec.PodSelector); err != nil {
					return fmt.Errorf("failed to parse pod selector: %w", err)
				} else {
					destState.PodSelector = selector
				}
			}
			destStates = append(destStates, destState)
		}
		ruleState.Classifier = &Classifier{
			Destinations: destStates,
		}
		if ruleSpec.Classifier.Port.Protocol != "" {
			ruleState.Classifier.Protocol = protocol(ruleSpec.Classifier.Port.Protocol)
			if !ruleState.Classifier.Protocol.IsValid() {
				return fmt.Errorf("invalid protocol: %s, valid values are: tcp, udp, sctp", ruleSpec.Classifier.Port.Protocol)
			}
		}
		if ruleSpec.Classifier.Port.Port > 0 {
			port := int(ruleSpec.Classifier.Port.Port)
			ruleState.Classifier.Port = &port
		}
		rules = append(rules, ruleState)
	}
	desiredNQOSState.EgressRules = rules
	if err := desiredNQOSState.initAddressSets(c.addressSetFactory, c.controllerName); err != nil {
		return err
	}
	if err := c.deleteStaleQoSes(desiredNQOSState); err != nil {
		return err
	}
	if err := c.updateSourceAddresses(desiredNQOSState); err != nil {
		return err
	}
	if err := c.updateDestAddresses(desiredNQOSState); err != nil {
		return err
	}
	// since transact was successful we can finally replace the currentNQOSState in the cache with the latest desired one
	c.nqosCache[joinMetaNamespaceAndName(nqos.Namespace, nqos.Name)] = desiredNQOSState
	// TODO: update metrics
	// metrics.UpdateNetworkQoSCount(1)

	return nil
}

// clearNetworkQos will handle the logic for deleting all db objects related
// to the provided nqos which got deleted.
// uses externalIDs to figure out ownership
func (c *Controller) clearNetworkQos(nqosNamespace, nqosName string) error {
	cachedName := joinMetaNamespaceAndName(nqosNamespace, nqosName)

	// See if we need to handle this: https://github.com/ovn-org/ovn-kubernetes/pull/3659#discussion_r1284645817
	qosState, loaded := c.nqosCache[cachedName]
	if !loaded {
		// there is no existing NQOS configured with this name, nothing to clean
		klog.Infof("NQOS %s not found in cache, nothing to clear", cachedName)
		return nil
	}

	// clear NBDB objects for the given NQOS
	// TODO: remove address sets from ovn nb
	// TODO: to be implemented...
	if err := c.deleteQoSes(qosState); err != nil {
		return fmt.Errorf("failed to delete QoS rules for NetworkQoS %s/%s: %w", qosState.namespace, qosState.name, err)
	}

	delete(c.nqosCache, cachedName)
	// metrics.UpdateNetworkQoSCount(-1)

	return nil
}

const (
	conditionTypeReady    = "Ready-In-Zone-"
	reasonQoSSetupSuccess = "Success"
	reasonQoSSetupFailed  = "Failed"
)

func (c *Controller) updateNQOSStatusToReady(namespace, name string) error {
	cond := metav1.Condition{
		Type:    conditionTypeReady + c.zone,
		Status:  metav1.ConditionTrue,
		Reason:  reasonQoSSetupSuccess,
		Message: "NetworkQoS was applied successfully",
	}
	err := c.updateNQOStatusCondition(cond, namespace, name)
	if err != nil {
		return fmt.Errorf("failed to update the status of NetworkQoS %s/%s, err: %v", namespace, name, err)
	}
	klog.V(5).Infof("Patched the status of NetworkQoS %s/%s with condition type %v/%v",
		namespace, name, conditionTypeReady+c.zone, metav1.ConditionTrue)
	return nil
}

func (c *Controller) updateNQOSStatusToNotReady(namespace, name, errMsg string) error {
	cond := metav1.Condition{
		Type:    conditionTypeReady + c.zone,
		Status:  metav1.ConditionFalse,
		Reason:  reasonQoSSetupFailed,
		Message: fmt.Sprintf("Failed to apply NetworkQoS: %s", errMsg),
	}
	err := c.updateNQOStatusCondition(cond, namespace, name)
	if err != nil {
		return fmt.Errorf("failed to update the status of NetworkQoS %s/%s, err: %v", namespace, name, err)
	}
	klog.V(5).Infof("Patched the status of NetworkQoS %s/%s with condition type %v/%v",
		namespace, name, conditionTypeReady+c.zone, metav1.ConditionTrue)
	return nil
}

func (c *Controller) updateNQOStatusCondition(newCondition metav1.Condition, namespace, name string) error {
	nqos, err := c.nqosLister.NetworkQoSes(namespace).Get(name)
	if err != nil {
		return err
	}
	existingCondition := meta.FindStatusCondition(nqos.Status.Conditions, newCondition.Type)
	if existingCondition == nil {
		newCondition.LastTransitionTime = metav1.NewTime(time.Now())
	} else {
		if existingCondition.Status != newCondition.Status {
			existingCondition.Status = newCondition.Status
			existingCondition.LastTransitionTime = metav1.NewTime(time.Now())
		}
		existingCondition.Reason = newCondition.Reason
		existingCondition.Message = newCondition.Message
		newCondition = *existingCondition
	}
	applyObj := nqosapiapply.NetworkQoS(name, namespace).
		WithStatus(nqosapiapply.Status().WithConditions(newCondition))
	_, err = c.nqosClientSet.K8sV1().NetworkQoSes(namespace).ApplyStatus(context.TODO(), applyObj, metav1.ApplyOptions{FieldManager: c.zone, Force: true})
	return err
}

func (c *Controller) getSourceIPs(nqosState *networkQoSState) ([]string, error) {
	if nqosState.PodSelector == nil {
		return nil, fmt.Errorf("function getSourceIPs shouldn't be called if source pod selector is empty")
	}
	pods, err := c.nqosPodLister.Pods(nqosState.namespace).List(nqosState.PodSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}
	addresses := []string{}
	for _, pod := range pods {
		podAddresses, err := getPodAddresses(pod, nqosState.networkAttachmentName)
		if err != nil {
			return nil, fmt.Errorf("failed to get addresses of pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		if len(podAddresses) > 0 {
			addresses = append(addresses, podAddresses...)
		}
	}
	return addresses, nil
}

func (c *Controller) getDestIPs(nqosState *networkQoSState, dest *Destination) ([]string, error) {
	namespaces := []string{}
	if dest.NamespaceSelector == nil {
		namespaces = append(namespaces, nqosState.namespace)
	} else {
		nsList, err := c.nqosNamespaceLister.List(dest.NamespaceSelector)
		if err != nil {
			return nil, fmt.Errorf("failed to get namespaces by %s: %w", dest.NamespaceSelector.String(), err)
		}
		for _, ns := range nsList {
			namespaces = append(namespaces, ns.Name)
		}
	}
	podSelector := labels.Everything()
	if dest.PodSelector != nil {
		podSelector = dest.PodSelector
	}
	addresses := []string{}
	for _, ns := range namespaces {
		pods, err := c.nqosPodLister.Pods(ns).List(podSelector)
		if err != nil {
			return nil, fmt.Errorf("failed to get pods in namespace %s: %w", ns, err)
		}
		for _, pod := range pods {
			podAddresses, err := getPodAddresses(pod, nqosState.networkAttachmentName)
			if err != nil {
				return nil, fmt.Errorf("failed to get addresses of pod %s/%s: %w", pod.Namespace, pod.Name, err)
			}
			if len(podAddresses) > 0 {
				addresses = append(addresses, podAddresses...)
			}
		}
	}
	return addresses, nil
}
