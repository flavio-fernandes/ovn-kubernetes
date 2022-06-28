package zoneinterconnect

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

type ZoneChassisHandler struct {
	sbClient libovsdbclient.Client
}

func NewZoneChassisHandler(sbClient libovsdbclient.Client) *ZoneChassisHandler {
	return &ZoneChassisHandler{
		sbClient: sbClient,
	}
}

// AddLocalZoneNode marks the chassis entry for the node in the SB DB to a local chassis
func (zch *ZoneChassisHandler) AddLocalZoneNode(node *corev1.Node) error {
	// Get the chassis id.
	chassisId, err := util.ParseNodeChassisIDAnnotation(node)
	if err != nil {
		return fmt.Errorf("failed to parse node chassis-id for node - %s, error: %v", node.Name, err)
	}

	// Update the node chassis to local.
	if err := libovsdbops.UpdateChassisToLocal(zch.sbClient, node.Name, chassisId); err != nil {
		return fmt.Errorf("failed to update remote chassis into local %s, error: %v", node.Name, err)
	}

	return nil
}

// AddRemoteZoneNode creates the remote chassis for the remote zone node node in the SB DB or marks
// the entry as remote if it was local chassis earlier
func (zch *ZoneChassisHandler) AddRemoteZoneNode(node *corev1.Node) error {
	// Get the chassis id.
	chassisId, err := util.ParseNodeChassisIDAnnotation(node)
	if err != nil {
		return fmt.Errorf("failed to parse node chassis-id for node - %s, error: %v", node.Name, err)
	}

	nodePrimaryIp, err := util.GetNodePrimaryIP(node)
	if err != nil {
		return fmt.Errorf("failed to parse node %s primary IP %v", node.Name, err)
	}

	if err := libovsdbops.CreateOrUpdateRemoteChassis(zch.sbClient, node.Name, chassisId, nodePrimaryIp); err != nil {
		return fmt.Errorf("failed to create encaps and remote chassis in SBDB for node %s, error: %v", node.Name, err)
	}

	return nil
}

// DeleteNode deletes the remote chassis (if it exists) for the node.
func (zch *ZoneChassisHandler) DeleteNode(node *corev1.Node) error {
	chassisId, err := util.ParseNodeChassisIDAnnotation(node)
	if err != nil {
		return fmt.Errorf("failed to parse node chassis-id for node - %s, error: %v", node.Name, err)
	}

	libovsdbops.CleanupRemoteChassis(zch.sbClient, node.Name, chassisId)
	return nil
}
