package acl

import (
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"

	"github.com/pkg/errors"

	"k8s.io/klog/v2"
)

func PurgeRejectRules(modelClient libovsdbops.ModelClient) error {
	acls, err := libovsdbops.FindRejectACLs(modelClient.GetClient())
	if err != nil {
		return errors.Wrap(err, "Error while finding rejct ACLs")
	}
	// Try to remove all reject ACLs from all logical Switches
	for _, acl := range acls {
		switchesWithACL := func(item *nbdb.LogicalSwitch) bool {
			for _, itemAcl := range item.ACLs {
				if itemAcl == acl.UUID {
					return true
				}
			}
			return false
		}

		ls, err := libovsdbops.FindSwitch(modelClient.GetClient(), switchesWithACL)
		if err != nil {
			return errors.Wrapf(err, "Error while querying ACLs uuid:%s with reject action: %s", acl.UUID, err)
		}

		err = libovsdbops.RemoveACLFromSwitches(modelClient, ls, acl.UUID)
		if err != nil {
			return errors.Wrapf(err, "Failed to remove reject acl from logical switches")
		}
	}

	err = libovsdbops.DeleteACLsFromPortGroup(modelClient.GetClient(), types.ClusterPortGroupName, acls...)
	if err != nil {
		klog.Errorf("Error trying to remove ACLs %+v from port group %s: %v", acls, types.ClusterPortGroupName, err)
	}

	return nil
}
