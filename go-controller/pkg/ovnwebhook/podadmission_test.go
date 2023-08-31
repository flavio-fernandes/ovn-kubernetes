package ovnwebhook

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	v1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubevirtv1 "kubevirt.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestPodAdmission_ValidateUpdate(t *testing.T) {

	const podName = "testpod"

	tests := []struct {
		name        string
		node        *corev1.Node
		ctx         context.Context
		oldObj      runtime.Object
		newObj      runtime.Object
		expectedErr error
	}{
		{
			name: "allow if user is not ovnkube-node",
			node: &corev1.Node{},
			ctx: admission.NewContextWithRequest(context.TODO(), admission.Request{
				AdmissionRequest: v1.AdmissionRequest{UserInfo: authenticationv1.UserInfo{
					Username: "system:nodes:node",
				}},
			}),
			oldObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:   podName,
					Labels: map[string]string{"key": "old"},
				},
			},
			newObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:   podName,
					Labels: map[string]string{"key": "new"},
				},
			},
			expectedErr: nil,
		},
		{
			name: "error out if the request is not in context",
			node: &corev1.Node{},
			ctx:  context.TODO(),
			oldObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: podName,
				},
			},
			newObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{"new": "value"},
				},
			},
			expectedErr: errors.New("admission.Request not found in context"),
		},
		{
			name: "ovnkube-node cannot modify annotations on pods running on different nodes",
			node: &corev1.Node{},
			ctx: admission.NewContextWithRequest(context.TODO(), admission.Request{
				AdmissionRequest: v1.AdmissionRequest{UserInfo: authenticationv1.UserInfo{
					Username: userName + "_rougeOne",
				}},
			}),
			oldObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{util.OvnPodAnnotationName: "old"},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
			newObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{util.OvnPodAnnotationName: "new"},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
			expectedErr: fmt.Errorf("ovnkube-node on node: %q is not allowed to modify pods %q annotations", nodeName+"_rougeOne", podName),
		},
		{
			name: "ovnkube-node cannot modify pod annotations that do not belong to it",
			node: &corev1.Node{},
			ctx: admission.NewContextWithRequest(context.TODO(), admission.Request{
				AdmissionRequest: v1.AdmissionRequest{UserInfo: authenticationv1.UserInfo{
					Username: userName,
				}},
			}),
			oldObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{util.OvnPodAnnotationName + "bad": "old"},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
			newObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{util.OvnPodAnnotationName + "bad": "new"},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
			expectedErr: fmt.Errorf("ovnkube-node on node: %q is not allowed to set at least one of the annotations on pod: %q: %v", nodeName, podName, []string{util.OvnPodAnnotationName + "bad"}),
		},
		{
			name: "ovnkube-node can modify OvnPodAnnotationName annotation on a pod",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        nodeName,
					Annotations: map[string]string{"k8s.ovn.org/node-subnets": `{"default":"192.168.0.0/24"}`},
				},
			},
			ctx: admission.NewContextWithRequest(context.TODO(), admission.Request{
				AdmissionRequest: v1.AdmissionRequest{UserInfo: authenticationv1.UserInfo{
					Username: userName,
				}},
			}),
			oldObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{util.OvnPodAnnotationName: `{"default":{"ip_addresses":["192.168.0.5/24"],"mac_address":"0a:58:0a:80:00:05"}}`},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
			newObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{util.OvnPodAnnotationName: `{"default":{"ip_addresses":["192.168.0.10/24"],"mac_address":"0a:58:0a:80:00:05"}}`},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
		},
		{
			name: "ovnkube-node cannot modify an IP in the OvnPodAnnotationName annotation to an invalid value",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        nodeName,
					Annotations: map[string]string{"k8s.ovn.org/node-subnets": `{"default":"192.168.0.0/24"}`},
				},
			},
			ctx: admission.NewContextWithRequest(context.TODO(), admission.Request{
				AdmissionRequest: v1.AdmissionRequest{UserInfo: authenticationv1.UserInfo{
					Username: userName,
				}},
			}),
			oldObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{util.OvnPodAnnotationName: `{"default":{"ip_addresses":["192.168.0.5/24"],"mac_address":"0a:58:0a:80:00:05"}}`},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
			newObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{util.OvnPodAnnotationName: `{"default":{"ip_addresses":["10.10.10.10/24"],"mac_address":"0a:58:0a:80:00:05"}}`},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
			expectedErr: fmt.Errorf("ovnkube-node on node: %q is not allowed to set %s on pod %q: 10.10.10.10/24 does not belong to %s node", nodeName, util.OvnPodAnnotationName, podName, nodeName),
		},
		{
			name: "ovnkube-node can use an IP in OvnPodAnnotationName annotation that belongs to a different node in kubevirt live-migration",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        nodeName,
					Annotations: map[string]string{"k8s.ovn.org/node-subnets": `{"default":"192.168.0.0/24"}`},
				},
			},
			ctx: admission.NewContextWithRequest(context.TODO(), admission.Request{
				AdmissionRequest: v1.AdmissionRequest{UserInfo: authenticationv1.UserInfo{
					Username: userName,
				}},
			}),
			oldObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{kubevirtv1.AllowPodBridgeNetworkLiveMigrationAnnotation: ""},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
			newObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: podName,
					Annotations: map[string]string{util.OvnPodAnnotationName: `{"default":{"ip_addresses":["10.10.10.10/24"],"mac_address":"0a:58:0a:80:00:05"}}`,
						kubevirtv1.AllowPodBridgeNetworkLiveMigrationAnnotation: ""},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
		},
		{
			name: "ovnkube-node can modify DPUConnectionDetailsAnnot annotation on a pod",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        nodeName,
					Annotations: map[string]string{"k8s.ovn.org/node-subnets": `{"default":"192.168.0.0/24"}`},
				},
			},
			ctx: admission.NewContextWithRequest(context.TODO(), admission.Request{
				AdmissionRequest: v1.AdmissionRequest{UserInfo: authenticationv1.UserInfo{
					Username: userName,
				}},
			}),
			oldObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{util.DPUConnectionDetailsAnnot: "old"},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
			newObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{util.DPUConnectionDetailsAnnot: "new"},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
		},
		{
			name: "ovnkube-node can modify DPUConnetionStatusAnnot annotation on a pod",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        nodeName,
					Annotations: map[string]string{"k8s.ovn.org/node-subnets": `{"default":"192.168.0.0/24"}`},
				},
			},
			ctx: admission.NewContextWithRequest(context.TODO(), admission.Request{
				AdmissionRequest: v1.AdmissionRequest{UserInfo: authenticationv1.UserInfo{
					Username: userName,
				}},
			}),
			oldObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{util.DPUConnetionStatusAnnot: "old"},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
			newObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{util.DPUConnetionStatusAnnot: "new"},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
		},
		{
			name: "ovnkube-node cannot modify anything other than pods annotations",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        nodeName,
					Annotations: map[string]string{"k8s.ovn.org/node-subnets": `{"default":"192.168.0.0/24"}`},
				},
			},
			ctx: admission.NewContextWithRequest(context.TODO(), admission.Request{
				AdmissionRequest: v1.AdmissionRequest{UserInfo: authenticationv1.UserInfo{
					Username: userName,
				}},
			}),
			oldObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{util.OvnPodAnnotationName: `{"default":{"ip_addresses":["192.168.0.5/24"],"mac_address":"0a:58:0a:80:00:05"}}`},
					Labels:      map[string]string{"key": "old"},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
			newObj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        podName,
					Annotations: map[string]string{util.OvnPodAnnotationName: `{"default":{"ip_addresses":["192.168.0.10/24"],"mac_address":"0a:58:0a:80:00:05"}}`},
					Labels:      map[string]string{"key": "new"},
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			},
			expectedErr: fmt.Errorf("ovnkube-node on node: %q is not allowed to modify anything other than annotations", nodeName),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithRuntimeObjects(tt.node).Build()
			padm := NewPodAdmissionWebhook(client)
			_, err := padm.ValidateUpdate(tt.ctx, tt.oldObj, tt.newObj)
			if !reflect.DeepEqual(err, tt.expectedErr) {
				t.Errorf("ValidateUpdate() error = %v, expectedErr %v", err, tt.expectedErr)
				return
			}
		})
	}
}
