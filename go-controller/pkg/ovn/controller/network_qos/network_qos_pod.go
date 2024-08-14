package networkqos

import (
	"fmt"
	"strings"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

func (c *Controller) processNextNQOSPodWorkItem(wg *sync.WaitGroup) bool {
	wg.Add(1)
	defer wg.Done()
	nqosPodKey, quit := c.nqosPodQueue.Get()
	if quit {
		return false
	}
	defer c.nqosPodQueue.Done(nqosPodKey)
	err := c.syncNetworkQoSPod(nqosPodKey.(string))
	if err == nil {
		c.nqosPodQueue.Forget(nqosPodKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with: %v", nqosPodKey, err))

	if c.nqosPodQueue.NumRequeues(nqosPodKey) < maxRetries {
		c.nqosPodQueue.AddRateLimited(nqosPodKey)
		return true
	}

	c.nqosPodQueue.Forget(nqosPodKey)
	return true
}

// syncNetworkQoSPod decides the main logic everytime
// we dequeue a key from the nqosPodQueue cache
func (c *Controller) syncNetworkQoSPod(key string) error {
	c.Lock()
	defer c.Unlock()
	startTime := time.Now()
	// Iterate all NQOses and check if this namespace start/stops matching
	// any NQOS and add/remove the setup accordingly. Namespaces can match multiple
	// NQOses objects, so continue iterating all NQOS objects before finishing.
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	klog.V(5).Infof("Processing sync for Pod %s/%s in Network QoS controller", namespace, name)

	defer func() {
		klog.V(5).Infof("Finished syncing Pod %s/%s Network QoS controller: took %v", namespace, name, time.Since(startTime))
	}()
	ns, err := c.nqosNamespaceLister.Get(namespace)
	if err != nil {
		return err
	}
	podNamespaceLister := c.nqosPodLister.Pods(namespace)
	pod, err := podNamespaceLister.Get(name)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	// (i) pod add
	// (ii) pod update because LSP and IPAM is done OR pod's labels changed
	// (iii) pod update because pod went into completed state
	// (iv) pod delete
	// In all these cases check which NQOSes were managing this pod and enqueue them back to nqosQueue
	existingNQOSses, err := c.nqosLister.List(labels.Everything())
	if err != nil {
		return err
	}
	// case(iii)/(iv)
	if pod == nil || util.PodCompleted(pod) {
		for _, nqos := range existingNQOSses {
			cachedName := joinMetaNamespaceAndName(nqos.Namespace, nqos.Name)
			nqosObj, loaded := c.nqosCache[cachedName]
			if !loaded {
				continue
			}
			c.clearPodForNQOS(namespace, name, nqosObj, c.nqosQueue)
		}
		return nil
	}
	// We don't want to shortcuit only local zone pods here since peer pods
	// whether local or remote need to be dealt with. So we let the main
	// NQOS controller take care of the local zone pods logic for the policy subjects
	if !util.PodScheduled(pod) || util.PodWantsHostNetwork(pod) {
		// we don't support NQOS with host-networked pods
		// if pod is no scheduled yet, return and we can process it on its next update
		// because anyways at that stage pod is considered to belong to remote zone
		return nil
	}
	// case (i)/(ii)
	for _, nqos := range existingNQOSses {
		cachedName := joinMetaNamespaceAndName(nqos.Namespace, nqos.Name)
		nqosObj, loaded := c.nqosCache[cachedName]
		if !loaded {
			klog.Warningf("NetworkQoS not synced yet: %s", cachedName)
			c.nqosQueue.Add(cachedName)
			continue
		}
		// TODO: is pod disqualified nqos source pod selector or dest selectors and pod in the cache
		c.setPodForNQOS(pod, nqosObj, ns, c.nqosQueue)
	}
	return nil
}

// clearPodForNQOS will handle the logic for figuring out if the provided pod name
// TODO...
func (c *Controller) clearPodForNQOS(namespace, name string, nqosState *networkQoSState, queue workqueue.RateLimitingInterface) {
	// TODO: Implement-me!
	fullPodName := joinMetaNamespaceAndName(namespace, name)
	if err := nqosState.removePodFromSource(c, fullPodName); err != nil {
		klog.Error(err)
		queue.AddRateLimited(fullPodName)
		return
	}
	// remove pod from destination address set
	for _, rule := range nqosState.EgressRules {
		if rule.Classifier == nil {
			continue
		}
		for _, dest := range rule.Classifier.Destinations {
			if err := dest.removePod(fullPodName); err != nil {
				klog.Error(err)
				queue.AddRateLimited(fullPodName)
				return
			}
		}
	}
}

// setPodForNQOS will handle the logic for figuring out if the provided pod name
// TODO...
func (c *Controller) setPodForNQOS(pod *v1.Pod, nqosState *networkQoSState, namespace *v1.Namespace, queue workqueue.RateLimitingInterface) {
	fullPodName := joinMetaNamespaceAndName(pod.Namespace, pod.Name)
	addresses, err := getPodAddresses(pod, nqosState.networkAttachmentName)
	if err == nil && addresses == nil {
		// pod hasn't been annotated with addresses yet, return without retry
		return
	} else if err != nil {
		klog.Errorf("Failed to parse addresses for pod %s/%s, network %s, err: %v", pod.Namespace, pod.Name, nqosState.networkAttachmentName, err)
		queue.AddRateLimited(fullPodName)
		return
	}
	if eligibleSource := nqosState.isEligibleSource(pod); eligibleSource {
		err = nqosState.addPodToSource(c, pod, addresses)
	} else if nqosState.hasSource(pod) {
		err = nqosState.removePodFromSource(c, fullPodName)
	}
	if err != nil {
		klog.Error(err)
		queue.AddRateLimited(fullPodName)
		return
	}
	err = reconcilePodForDestinations(nqosState, namespace, pod, addresses)
	if err != nil {
		klog.Error(err)
		queue.AddRateLimited(fullPodName)
	}
}

func (c *Controller) setPodForNQOS1(pod *v1.Pod, nqosCache *networkQoSState, namespace *v1.Namespace, queue workqueue.RateLimitingInterface) {
	// TODO: Implement-me!
	fullPodName := joinMetaNamespaceAndName(pod.Namespace, pod.Name)
	addresses, err := getPodAddresses(pod, nqosCache.networkAttachmentName)
	if err == nil && addresses == nil {
		// pod hasn't been annotated with addresses yet, return without retry
		return
	} else if err != nil {
		klog.Errorf("Failed to parse addresses for pod %s/%s, network %s, err: %v", pod.Namespace, pod.Name, nqosCache.networkAttachmentName, err)
		queue.AddRateLimited(fullPodName)
		return
	}

	if nqosCache.PodSelector != nil && nqosCache.PodSelector.Matches(labels.Set(pod.Labels)) {
		// match source, add to non-namespace source address set
		if err := nqosCache.SrcAddrSet.AddAddresses(addresses); err != nil {
			klog.Errorf("Failed to add addresses {%s} to source address set %s for NetworkQoS %s/%s: %v", strings.Join(addresses, ","), nqosCache.SrcAddrSet.GetName(), nqosCache.namespace, nqosCache.name, err)
			queue.AddRateLimited(fullPodName)
			return
		}
		nqosCache.Pods.Store(fullPodName, addresses)
		switchName := ""
		if pod.Spec.NodeName != "" {
			node, err := c.nqosNodeLister.Get(pod.Spec.NodeName)
			if err != nil {
				klog.Errorf("Failed to look up node %s: %v", pod.Spec.NodeName, err)
				queue.AddRateLimited(fullPodName)
				return
			}
			if c.isNodeInLocalZone(node) {
				switchName = c.GetNetworkScopedSwitchName(pod.Spec.NodeName)
			}
		}
		// add qos rule to logical switch
		if switchName != "" {
			if err := c.addQoSToLogicalSwitch(nqosCache, switchName); err != nil {
				klog.Error(err)
				queue.AddRateLimited(fullPodName)
				return
			}
		}
		//[need confirm]: if pod is selected by source, not necessary to destination processing
		return
	}
	// add pod to egress rules
	for _, rule := range nqosCache.EgressRules {
		for index, dest := range rule.Classifier.Destinations {
			if !dest.matchNamespace(namespace, nqosCache.namespace) {
				continue
			}
			if !dest.matchPod(pod) {
				continue
			}
			// add ip to address set
			if err := dest.DestAddrSet.AddAddresses(addresses); err != nil {
				klog.Errorf("Failed to add addresses {%s} to dest address set %s for NetworkQoS %s/%s, rule index %d: %v", strings.Join(addresses, ","), nqosCache.SrcAddrSet.GetName(), nqosCache.namespace, nqosCache.name, index, err)
				queue.AddRateLimited(fullPodName)
				return
			}
			// add pod to map
			dest.Pods.Store(fullPodName, addresses)
		}
	}
}

func reconcilePodForDestinations(nqosState *networkQoSState, podNs *v1.Namespace, pod *v1.Pod, addresses []string) error {
	fullPodName := joinMetaNamespaceAndName(pod.Namespace, pod.Name)
	for _, rule := range nqosState.EgressRules {
		for index, dest := range rule.Classifier.Destinations {
			if !dest.matchNamespace(podNs, nqosState.namespace) {
				continue
			}
			if dest.matchPod(pod) {
				// add pod address to address set
				if err := dest.addPod(fullPodName, addresses); err != nil {
					return fmt.Errorf("failed to add addresses {%s} to dest address set %s for NetworkQoS %s/%s, rule index %d: %v", strings.Join(addresses, ","), nqosState.SrcAddrSet.GetName(), nqosState.namespace, nqosState.name, index, err)
				}
				// add pod to map
				dest.Pods.Store(fullPodName, addresses)
			} else {
				// no match, remove the pod if it's previously selected
				if err := dest.removePod(fullPodName); err != nil {
					return fmt.Errorf("failed to delete addresses {%s} from dest address set %s for NetworkQoS %s/%s, rule index %d: %v", strings.Join(addresses, ","), dest.DestAddrSet.GetName(), nqosState.namespace, nqosState.name, index, err)
				}
			}
		}
	}
	return nil
}
