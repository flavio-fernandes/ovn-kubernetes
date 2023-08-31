package ovnwebhook

import (
	"context"
	"fmt"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kubevirt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"golang.org/x/exp/maps"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type checkPodAnnot func(client crclient.Client, v annotationChange, pod *corev1.Pod, nodeName string) error

// interconnectPodAnnotationChecks holds annotations allowed for ovnkube-node:<nodeName> users in IC environments
var interconnectPodAnnotations = map[string]checkPodAnnot{
	util.OvnPodAnnotationName: func(client crclient.Client, v annotationChange, pod *corev1.Pod, nodeName string) error {
		// Ignore kubevirt pods with live migration, the IP can cross node-subnet boundaries
		if kubevirt.IsPodLiveMigratable(pod) {
			return nil
		}

		podAnnot, err := util.UnmarshalPodAnnotation(map[string]string{util.OvnPodAnnotationName: v.value}, types.DefaultNetworkName)
		if err != nil {
			return err
		}
		node := &corev1.Node{}

		if err := client.Get(context.TODO(), apitypes.NamespacedName{Name: nodeName}, node); err != nil {
			return err
		}
		if err != nil {
			return err
		}

		subnets, err := util.ParseNodeHostSubnetAnnotation(node, types.DefaultNetworkName)
		if err != nil {
			return err
		}
		for _, ip := range podAnnot.IPs {
			found := false
			for _, subnet := range subnets {
				if subnet.Contains(ip.IP) {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("%s does not belong to %s node", ip, nodeName)
			}
		}
		return nil
	},
	util.DPUConnectionDetailsAnnot: nil,
	util.DPUConnetionStatusAnnot:   nil,
}

type PodAdmission struct {
	client         crclient.Client
	annotations    map[string]checkPodAnnot
	annotationKeys sets.Set[string]
}

func NewPodAdmissionWebhook(client crclient.Client) *PodAdmission {
	return &PodAdmission{
		client:         client,
		annotations:    interconnectPodAnnotations,
		annotationKeys: sets.New[string](maps.Keys(interconnectPodAnnotations)...),
	}
}

func (p PodAdmission) ValidateCreate(ctx context.Context, obj runtime.Object) (warnings admission.Warnings, err error) {
	// Ignore creation, the webhook is configured to only handle pod/status updates
	return nil, nil
}

func (p PodAdmission) ValidateDelete(_ context.Context, _ runtime.Object) (warnings admission.Warnings, err error) {
	// Ignore creation, the webhook is configured to only handle pod/status updates
	return nil, nil
}

var _ admission.CustomValidator = &PodAdmission{}

func (p PodAdmission) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (warnings admission.Warnings, err error) {
	oldPod := oldObj.(*corev1.Pod)
	newPod := newObj.(*corev1.Pod)

	changes := mapDiff(oldPod.Annotations, newPod.Annotations)
	changedKeys := maps.Keys(changes)

	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return nil, err
	}
	nodeName, isOVNKubeNode := ovnkubeNodeIdentity(req.UserInfo)

	if !isOVNKubeNode {
		// the user is not an ovnkube-node
		return nil, nil
	}

	if oldPod.Spec.NodeName != nodeName {
		return nil, fmt.Errorf("ovnkube-node on node: %q is not allowed to modify pods %q annotations", nodeName, oldPod.Name)
	}
	if newPod.Spec.NodeName != nodeName {
		return nil, fmt.Errorf("ovnkube-node on node: %q is not allowed to modify pods %q annotations", nodeName, newPod.Name)
	}

	// ovnkube-node is not allowed to change annotations outside of it's scope
	if !p.annotationKeys.HasAll(changedKeys...) {
		return nil, fmt.Errorf("ovnkube-node on node: %q is not allowed to set at least one of the annotations on pod: %q: %v", nodeName, newPod.Name, changedKeys)
	}

	for _, key := range changedKeys {
		if check := p.annotations[key]; check != nil {
			if err := check(p.client, changes[key], newPod, nodeName); err != nil {
				return nil, fmt.Errorf("ovnkube-node on node: %q is not allowed to set %s on pod %q: %v", nodeName, key, newPod.Name, err)
			}
		}
	}

	// Verify that nothing but the annotations changed.
	// Since ovnkube-node only has the pod/status permissions, it is enough to check .Status and .ObjectMeta only.
	// Ignore .ManagedFields fields which are modified on every update.
	oldPodShallowCopy := oldPod
	newPodShallowCopy := newPod
	oldPodShallowCopy.Annotations = nil
	newPodShallowCopy.Annotations = nil
	oldPodShallowCopy.ManagedFields = nil
	newPodShallowCopy.ManagedFields = nil
	if !apiequality.Semantic.DeepEqual(oldPodShallowCopy.ObjectMeta, newPodShallowCopy.ObjectMeta) ||
		!apiequality.Semantic.DeepEqual(oldPodShallowCopy.Status, newPodShallowCopy.Status) {
		return nil, fmt.Errorf("ovnkube-node on node: %q is not allowed to modify anything other than annotations", nodeName)
	}

	return nil, nil
}
