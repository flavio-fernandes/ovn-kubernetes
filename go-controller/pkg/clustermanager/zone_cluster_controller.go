package clustermanager

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	corev1 "k8s.io/api/core/v1"
	cache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	objretry "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/retry"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

const (
	// Maximum node Ids that can be generated. Limited to maximum nodes supported by k8s.
	maxNodeIds = 5000
)

// zoneClusterController is the cluster controller for the zone(s).
// It listens to the node events and allocates zone related annotations
// to each node. Below are the zone related annotations
//   - id for each node.
type zoneClusterController struct {
	kube         kube.Interface
	watchFactory *factory.WatchFactory
	stopChan     chan struct{}
	wg           *sync.WaitGroup

	// node events factory handler
	nodeHandler *factory.Handler

	// retry framework for nodes
	retryNodes *objretry.RetryFramework

	idAllocator *IdAllocator
}

func newZoneClusterController(ovnClient *util.OVNClusterManagerClientset, wf *factory.WatchFactory) *zoneClusterController {

	kube := &kube.Kube{
		KClient: ovnClient.KubeClient,
	}

	wg := &sync.WaitGroup{}

	zcc := &zoneClusterController{
		kube:         kube,
		watchFactory: wf,
		stopChan:     make(chan struct{}),
		wg:           wg,
		idAllocator:  NewIdAlloctar("NodeIds", maxNodeIds),
	}

	zcc.initRetryFramework()
	return zcc
}

func (zcc *zoneClusterController) initRetryFramework() {
	zcc.retryNodes = zcc.newRetryFramework(factory.NodeType, true)
}

func (zcc *zoneClusterController) newRetryFramework(objectType reflect.Type, hasUpdateFunc bool) *objretry.RetryFramework {
	resourceHandler := &objretry.ResourceHandler{
		HasUpdateFunc:          hasUpdateFunc,
		NeedsUpdateDuringRetry: false,
		ObjType:                objectType,
		EventHandler: &zoneClusterControllerEventHandler{
			objType:  objectType,
			zcc:      zcc,
			syncFunc: nil,
		},
	}
	return objretry.NewRetryFramework(zcc.stopChan, zcc.wg, zcc.watchFactory, resourceHandler)
}

// Start starts the network cluster controller
// It does the following
//   - initializes the network subnet allocator ranges
//     and hybrid network subnet allocator ranges if hybrid overlay is enabled.
//   - Starts watching the kubernetes nodes
func (zcc *zoneClusterController) Start(ctx context.Context) error {
	nodeHandler, err := zcc.retryNodes.WatchResource()

	if err != nil {
		return fmt.Errorf("unable to watch nodes: %w", err)
	}

	zcc.nodeHandler = nodeHandler
	return err
}

func (zcc *zoneClusterController) Stop() {
	close(zcc.stopChan)
	zcc.wg.Wait()

	if zcc.nodeHandler != nil {
		zcc.watchFactory.RemoveNodeHandler(zcc.nodeHandler)
	}
}

// handleAddUpdateNodeEvent handles the add or update node event
func (zcc *zoneClusterController) handleAddUpdateNodeEvent(node *corev1.Node) error {
	allocatedNodeId, err := zcc.idAllocator.AllocateId(node.Name)
	if err != nil {
		return err
	}

	if allocatedNodeId == util.GetNodeId(node) {
		// Nothing to update.
		return nil
	}

	klog.V(5).Infof("Allocated id [%d] for node %q", allocatedNodeId, node.Name)
	return zcc.updateNodeAnnotationWithRetry(node.Name, allocatedNodeId)
}

// handleAddUpdateNodeEvent handles the delete node event
func (zcc *zoneClusterController) handleDeleteNode(node *corev1.Node) error {
	zcc.idAllocator.ReleaseId(node.Name)
	return nil
}

func (zcc *zoneClusterController) syncNodes(nodes []interface{}) error {
	return zcc.syncNodeIds(nodes)
}

func (zcc *zoneClusterController) syncNodeIds(nodes []interface{}) error {
	duplicateIdNodes := []string{}

	for _, tmp := range nodes {
		node, ok := tmp.(*corev1.Node)
		if !ok {
			return fmt.Errorf("spurious object in syncNodes: %v", tmp)
		}

		nodeId := util.GetNodeId(node)
		if nodeId != -1 {
			klog.V(5).Infof("Node %s has the id %d set", node.Name, nodeId)
			if err := zcc.idAllocator.ReserveId(node.Name, nodeId); err != nil {
				// The id set on this node is duplicate.
				klog.V(5).Infof("Node %s has a duplicate id [%d] set", node.Name, nodeId)
				duplicateIdNodes = append(duplicateIdNodes, node.Name)
			}
		}
	}

	for i := range duplicateIdNodes {
		newNodeId, err := zcc.idAllocator.AllocateId(duplicateIdNodes[i])
		if err != nil {
			return fmt.Errorf("failed to allocate id for node %s : err - %v", duplicateIdNodes[i], err)
		} else {
			klog.V(5).Infof("Allocated new id [%d] for node %q", newNodeId, duplicateIdNodes[i])
		}
	}

	return nil
}

func (zcc *zoneClusterController) updateNodeAnnotationWithRetry(nodeName string, nodeId int) error {
	// Retry if it fails because of potential conflict which is transient. Return error in the
	// case of other errors (say temporary API server down), and it will be taken care of by the
	// retry mechanism.
	resultErr := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// Informer cache should not be mutated, so get a copy of the object
		node, err := zcc.watchFactory.GetNode(nodeName)
		if err != nil {
			return err
		}

		cnode := node.DeepCopy()
		cnode.Annotations = util.UpdateNodeIdAnnotation(cnode.Annotations, nodeId)
		return zcc.kube.UpdateNode(cnode)
	})
	if resultErr != nil {
		return fmt.Errorf("failed to update node %s annotation", nodeName)
	}

	return nil
}

// zoneClusterControllerEventHandler object handles the events
// from retry framework.
type zoneClusterControllerEventHandler struct {
	objretry.EventHandler

	objType  reflect.Type
	zcc      *zoneClusterController
	syncFunc func([]interface{}) error
}

// zoneClusterControllerEventHandler functions

// AddResource adds the specified object to the cluster according to its type and
// returns the error, if any, yielded during object creation.
func (h *zoneClusterControllerEventHandler) AddResource(obj interface{}, fromRetryLoop bool) error {
	var err error

	switch h.objType {
	case factory.NodeType:
		node, ok := obj.(*corev1.Node)
		if !ok {
			return fmt.Errorf("could not cast %T object to *corev1.Node", obj)
		}
		if err = h.zcc.handleAddUpdateNodeEvent(node); err != nil {
			klog.Infof("Node add failed for %s, will try again later: %v",
				node.Name, err)
			return err
		}
	default:
		return fmt.Errorf("no add function for object type %s", h.objType)
	}
	return nil
}

// UpdateResource updates the specified object in the cluster to its version in newObj according
// to its type and returns the error, if any, yielded during the object update.
// The inRetryCache boolean argument is to indicate if the given resource is in the retryCache or not.
func (h *zoneClusterControllerEventHandler) UpdateResource(oldObj, newObj interface{}, inRetryCache bool) error {
	var err error

	switch h.objType {
	case factory.NodeType:
		node, ok := newObj.(*corev1.Node)
		if !ok {
			return fmt.Errorf("could not cast %T object to *corev1.Node", newObj)
		}
		if err = h.zcc.handleAddUpdateNodeEvent(node); err != nil {
			klog.Infof("Node update failed for %s, will try again later: %v",
				node.Name, err)
			return err
		}
	default:
		return fmt.Errorf("no update function for object type %s", h.objType)
	}
	return nil
}

// DeleteResource deletes the object from the cluster according to the delete logic of its resource type.
// cachedObj is the internal cache entry for this object, used for now for pods and network policies.
func (h *zoneClusterControllerEventHandler) DeleteResource(obj, cachedObj interface{}) error {
	switch h.objType {
	case factory.NodeType:
		node, ok := obj.(*corev1.Node)
		if !ok {
			return fmt.Errorf("could not cast obj of type %T to *knet.Node", obj)
		}
		return h.zcc.handleDeleteNode(node)
	}
	return nil
}

func (h *zoneClusterControllerEventHandler) SyncFunc(objs []interface{}) error {
	var syncFunc func([]interface{}) error

	if h.syncFunc != nil {
		// syncFunc was provided explicitly
		syncFunc = h.syncFunc
	} else {
		switch h.objType {
		case factory.NodeType:
			syncFunc = h.zcc.syncNodes

		default:
			return fmt.Errorf("no sync function for object type %s", h.objType)
		}
	}
	if syncFunc == nil {
		return nil
	}
	return syncFunc(objs)
}

// RecordAddEvent records the add event on this object. Not used here.
func (h *zoneClusterControllerEventHandler) RecordAddEvent(obj interface{}) {
}

// RecordUpdateEvent records the update event on this object. Not used here.
func (h *zoneClusterControllerEventHandler) RecordUpdateEvent(obj interface{}) {
}

// RecordDeleteEvent records the delete event on this object. Not used here.
func (h *zoneClusterControllerEventHandler) RecordDeleteEvent(obj interface{}) {
}

func (h *zoneClusterControllerEventHandler) RecordSuccessEvent(obj interface{}) {
}

// RecordErrorEvent records an error event on this object. Not used here.
func (h *zoneClusterControllerEventHandler) RecordErrorEvent(obj interface{}, reason string, err error) {
}

// isResourceScheduled returns true if the object has been scheduled.  Always returns true.
func (h *zoneClusterControllerEventHandler) IsResourceScheduled(obj interface{}) bool {
	return true
}

// IsObjectInTerminalState returns true if the object is a in terminal state.  Always returns true.
func (h *zoneClusterControllerEventHandler) IsObjectInTerminalState(obj interface{}) bool {
	return false
}

func (h *zoneClusterControllerEventHandler) AreResourcesEqual(obj1, obj2 interface{}) (bool, error) {
	// switch based on type
	if h.objType == factory.NodeType {
		node1, ok := obj1.(*corev1.Node)
		if !ok {
			return false, fmt.Errorf("could not cast obj1 of type %T to *corev1.Node", obj1)
		}
		node2, ok := obj2.(*corev1.Node)
		if !ok {
			return false, fmt.Errorf("could not cast obj2 of type %T to *corev1.Node", obj2)
		}

		// Check if the annotations have changed.
		node1Id := util.GetNodeId(node1)
		return (node1Id == util.GetNodeId(node2) && node1Id != -1), nil
	}

	return false, nil
}

// GetInternalCacheEntry returns the internal cache entry for this object
func (h *zoneClusterControllerEventHandler) GetInternalCacheEntry(obj interface{}) interface{} {
	return nil
}

// getResourceFromInformerCache returns the latest state of the object from the informers cache
// given an object key and its type
func (h *zoneClusterControllerEventHandler) GetResourceFromInformerCache(key string) (interface{}, error) {
	var obj interface{}
	var name string
	var err error

	_, name, err = cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to split key %s: %v", key, err)
	}

	switch h.objType {
	case factory.NodeType,
		factory.EgressNodeType:
		obj, err = h.zcc.watchFactory.GetNode(name)

	default:
		err = fmt.Errorf("object type %s not supported, cannot retrieve it from informers cache",
			h.objType)
	}
	return obj, err
}
