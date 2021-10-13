package acl

import (
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"github.com/pkg/errors"

	"k8s.io/klog/v2"
)

// RemoveACLFromNodeSwitches removes the ACL uuid entry from Logical Switch acl's list.
func RemoveACLFromNodeSwitches(switches []string, aclUUID string) error {
	if len(switches) == 0 {
		return nil
	}
	args := []string{}
	for _, ls := range switches {
		args = append(args, "--", "--if-exists", "remove", "logical_switch", ls, "acl", aclUUID)
	}
	_, _, err := util.RunOVNNbctl(args...)
	if err != nil {
		return errors.Wrapf(err, "Error while removing ACL: %s, from switches", aclUUID)
	}
	klog.Infof("ACL: %s, removed from switches: %s", aclUUID, switches)
	return nil
}

func PurgeRejectRules(nbClient libovsdbclient.Client) error {
	acls, err := libovsdbops.FindRejectACLs(nbClient)
	if err != nil {
		return errors.Wrap(err, "Error while finding rejct ACLs")
	}

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
			return errors.Wrapf(err, "Error while querying ACLs uuid:%s with reject action: %s", acl.UUID, stderr)
		}
		ls := strings.Split(data, "\n")
		err = RemoveACLFromNodeSwitches(ls, acl.UUID)
		if err != nil {
			return errors.Wrapf(err, "Failed to remove reject acl from logical switches")
		}
	}

	err = libovsdbops.DeleteACLsFromPortGroup(nbClient, types.ClusterPortGroupName, acls...)
	if err != nil {
		klog.Errorf("Error trying to remove ACLs %+v from port group %s: %v", acls, types.ClusterPortGroupName, err)
	}

	return nil
}
