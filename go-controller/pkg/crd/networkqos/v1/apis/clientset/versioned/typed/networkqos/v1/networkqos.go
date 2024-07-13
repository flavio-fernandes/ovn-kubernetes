/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Code generated by client-gen. DO NOT EDIT.

package v1

import (
	"context"
	json "encoding/json"
	"fmt"
	"time"

	v1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/networkqos/v1"
	networkqosv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/networkqos/v1/apis/applyconfiguration/networkqos/v1"
	scheme "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/networkqos/v1/apis/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// NetworkQoSesGetter has a method to return a NetworkQoSInterface.
// A group's client should implement this interface.
type NetworkQoSesGetter interface {
	NetworkQoSes(namespace string) NetworkQoSInterface
}

// NetworkQoSInterface has methods to work with NetworkQoS resources.
type NetworkQoSInterface interface {
	Create(ctx context.Context, networkQoS *v1.NetworkQoS, opts metav1.CreateOptions) (*v1.NetworkQoS, error)
	Update(ctx context.Context, networkQoS *v1.NetworkQoS, opts metav1.UpdateOptions) (*v1.NetworkQoS, error)
	UpdateStatus(ctx context.Context, networkQoS *v1.NetworkQoS, opts metav1.UpdateOptions) (*v1.NetworkQoS, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1.NetworkQoS, error)
	List(ctx context.Context, opts metav1.ListOptions) (*v1.NetworkQoSList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.NetworkQoS, err error)
	Apply(ctx context.Context, networkQoS *networkqosv1.NetworkQoSApplyConfiguration, opts metav1.ApplyOptions) (result *v1.NetworkQoS, err error)
	ApplyStatus(ctx context.Context, networkQoS *networkqosv1.NetworkQoSApplyConfiguration, opts metav1.ApplyOptions) (result *v1.NetworkQoS, err error)
	NetworkQoSExpansion
}

// networkQoSes implements NetworkQoSInterface
type networkQoSes struct {
	client rest.Interface
	ns     string
}

// newNetworkQoSes returns a NetworkQoSes
func newNetworkQoSes(c *K8sV1Client, namespace string) *networkQoSes {
	return &networkQoSes{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the networkQoS, and returns the corresponding networkQoS object, and an error if there is any.
func (c *networkQoSes) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.NetworkQoS, err error) {
	result = &v1.NetworkQoS{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("networkqoses").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of NetworkQoSes that match those selectors.
func (c *networkQoSes) List(ctx context.Context, opts metav1.ListOptions) (result *v1.NetworkQoSList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1.NetworkQoSList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("networkqoses").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested networkQoSes.
func (c *networkQoSes) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("networkqoses").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a networkQoS and creates it.  Returns the server's representation of the networkQoS, and an error, if there is any.
func (c *networkQoSes) Create(ctx context.Context, networkQoS *v1.NetworkQoS, opts metav1.CreateOptions) (result *v1.NetworkQoS, err error) {
	result = &v1.NetworkQoS{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("networkqoses").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(networkQoS).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a networkQoS and updates it. Returns the server's representation of the networkQoS, and an error, if there is any.
func (c *networkQoSes) Update(ctx context.Context, networkQoS *v1.NetworkQoS, opts metav1.UpdateOptions) (result *v1.NetworkQoS, err error) {
	result = &v1.NetworkQoS{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("networkqoses").
		Name(networkQoS.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(networkQoS).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *networkQoSes) UpdateStatus(ctx context.Context, networkQoS *v1.NetworkQoS, opts metav1.UpdateOptions) (result *v1.NetworkQoS, err error) {
	result = &v1.NetworkQoS{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("networkqoses").
		Name(networkQoS.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(networkQoS).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the networkQoS and deletes it. Returns an error if one occurs.
func (c *networkQoSes) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("networkqoses").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *networkQoSes) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("networkqoses").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched networkQoS.
func (c *networkQoSes) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.NetworkQoS, err error) {
	result = &v1.NetworkQoS{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("networkqoses").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// Apply takes the given apply declarative configuration, applies it and returns the applied networkQoS.
func (c *networkQoSes) Apply(ctx context.Context, networkQoS *networkqosv1.NetworkQoSApplyConfiguration, opts metav1.ApplyOptions) (result *v1.NetworkQoS, err error) {
	if networkQoS == nil {
		return nil, fmt.Errorf("networkQoS provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(networkQoS)
	if err != nil {
		return nil, err
	}
	name := networkQoS.Name
	if name == nil {
		return nil, fmt.Errorf("networkQoS.Name must be provided to Apply")
	}
	result = &v1.NetworkQoS{}
	err = c.client.Patch(types.ApplyPatchType).
		Namespace(c.ns).
		Resource("networkqoses").
		Name(*name).
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *networkQoSes) ApplyStatus(ctx context.Context, networkQoS *networkqosv1.NetworkQoSApplyConfiguration, opts metav1.ApplyOptions) (result *v1.NetworkQoS, err error) {
	if networkQoS == nil {
		return nil, fmt.Errorf("networkQoS provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(networkQoS)
	if err != nil {
		return nil, err
	}

	name := networkQoS.Name
	if name == nil {
		return nil, fmt.Errorf("networkQoS.Name must be provided to Apply")
	}

	result = &v1.NetworkQoS{}
	err = c.client.Patch(types.ApplyPatchType).
		Namespace(c.ns).
		Resource("networkqoses").
		Name(*name).
		SubResource("status").
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}