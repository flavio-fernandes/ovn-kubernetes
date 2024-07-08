package networkqos

import (
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	networkqosapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/networkqos/v1"
	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
)

// repairNetworkQoSes is called at startup and as the name suggests
// aims to repair the NBDB logical objects
// that are created for the network qoses in the cluster
func (c *Controller) repairNetworkQoSes() error {
	if !c.IsDefault() {
		klog.V(6).Infof("Default controller will repair NetworkQoses for all the networks.")
		return nil
	}
	start := time.Now()
	defer func() {
		klog.Infof("Repairing network qos took %v", time.Since(start))
	}()
	nqoses, err := c.nqosLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("unable to list NetworkQoSes from the lister: %v", err)
	}
	nqosMap := map[string]*networkqosapi.NetworkQoS{}
	for _, nqos := range nqoses {
		nqosMap[joinMetaNamespaceAndName(nqos.Namespace, nqos.Name, ":")] = nqos
	}
	nadMap := map[string]bool{}
	if config.OVNKubernetesFeature.EnableMultiNetwork {
		nads, err := c.nadLister.List(labels.Everything())
		if err != nil {
			return fmt.Errorf("unable to list net-attach-def from the lister: %v", err)
		}
		for _, nad := range nads {
			nadMap[joinMetaNamespaceAndName(nad.Namespace, nad.Name)] = true
		}
	}

	// find all ovn qos objects owned by NetworkQoS
	ovnQoSes, err := libovsdbops.FindQoSesWithPredicate(c.nbClient, func(qos *nbdb.QoS) bool {
		return qos.ExternalIDs[libovsdbops.OwnerTypeKey.String()] == string(libovsdbops.NetworkQoSOwnerType)
	})
	if err != nil {
		return fmt.Errorf("failed to look up qos in ovn: %w", err)
	}

	staleOvnQoSes := []*nbdb.QoS{}
	for _, ovnQos := range ovnQoSes {
		objName := ovnQos.ExternalIDs[libovsdbops.ObjectNameKey.String()]
		// doesn't have corresponding k8s name
		if objName == "" {
			klog.Warningf("Managed OVN QoS %s doesn't have key %s", ovnQos.UUID, libovsdbops.ObjectNameKey.String())
			staleOvnQoSes = append(staleOvnQoSes, ovnQos)
			continue
		}
		// clean up qoses whose k8s object has gone
		if _, exists := nqosMap[objName]; !exists {
			klog.Warningf("Managed OVN QoS %s doesn't have expected NetworkQoS object %s", ovnQos.UUID, objName)
			staleOvnQoSes = append(staleOvnQoSes, ovnQos)
			continue
		}
		// NetworkQoS's net-attach-def has gone
		nadName := ovnQos.ExternalIDs[types.NADExternalID]
		if _, exists := nadMap[nadName]; config.OVNKubernetesFeature.EnableMultiNetwork && nadName != "" && !exists {
			klog.Warningf("NetworkAttachmentDefinition %s for QoS %s/%s doesn't exist", nadName, objName, ovnQos.UUID)
			staleOvnQoSes = append(staleOvnQoSes, ovnQos)
			continue
		}
	}
	if len(staleOvnQoSes) == 0 {
		klog.V(4).Info("No invalid managed QoS found in OVN")
		return nil
	}

	for _, qos := range staleOvnQoSes {
		if err := c.deleteOvnQoSes([]*nbdb.QoS{qos}); err != nil {
			klog.Error(err)
		}
		if err := c.deleteAddressSetOnAllNetworks(qos.ExternalIDs[libovsdbops.ObjectNameKey.String()]); err != nil {
			klog.Error(err)
		}
	}
	return nil
}
