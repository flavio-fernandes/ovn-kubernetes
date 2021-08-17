package util

// Contains helper functions for OVN
// Eventually these should all be migrated to go-ovn bindings

import (
	"fmt"
	"net"
	"strings"
	"time"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/libovsdbops"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
)

// UpdateRouterSNAT checks if a NAT entry exists in OVN for a specific router and updates it if necessary.
func UpdateRouterSNAT(nbClient libovsdbclient.Client, router string, externalIP net.IP, logicalSubnet *net.IPNet) error {
	nat, err := libovsdbops.BuildRouterSNAT(&externalIP, logicalSubnet, "", nil)
	if err == nil {
		err = libovsdbops.AddOrUpdateNatsToRouter(nbClient, router, nat)
	}
	if err != nil {
		return fmt.Errorf("failed to create NAT rule for pod on router %s, "+
			"error: %v", router, err)
	}

	return nil
}

// CreateMACBinding Creates MAC binding in OVN SBDB
func CreateMACBinding(logicalPort, datapathName string, portMAC net.HardwareAddr, nextHop net.IP) error {
	datapath, err := GetDatapathUUID(datapathName)
	if err != nil {
		return err
	}

	// Check if exact match already exists
	stdout, stderr, err := RunOVNSbctl("--data=bare", "--no-heading", "--columns=_uuid", "find", "MAC_Binding",
		"logical_port="+logicalPort,
		fmt.Sprintf(`mac="%s"`, portMAC),
		"datapath="+datapath,
		fmt.Sprintf("ip=\"%s\"", nextHop))
	if err != nil {
		return fmt.Errorf("failed to check existence of MAC_Binding entry of (%s, %s, %s, %s)"+
			"stderr: %q, error: %v", datapath, logicalPort, portMAC, nextHop, stderr, err)
	}
	if stdout != "" {
		klog.Infof("The MAC_Binding entry of (%s, %s, %s, %s) exists with uuid %s",
			datapath, logicalPort, portMAC, nextHop, stdout)
		return nil
	}

	// Create new binding
	_, stderr, err = RunOVNSbctl("create", "mac_binding", "datapath="+datapath, fmt.Sprintf("ip=\"%s\"", nextHop),
		"logical_port="+logicalPort, fmt.Sprintf(`mac="%s"`, portMAC))
	if err != nil {
		return fmt.Errorf("failed to create a MAC_Binding entry of (%s, %s, %s, %s) "+
			"stderr: %q, error: %v", datapath, logicalPort, portMAC, nextHop, stderr, err)
	}

	return nil
}

// GetDatapathUUID returns the OVN SBDB UUID for a datapath
func GetDatapathUUID(datapathName string) (string, error) {
	// Get datapath from southbound, depending on startup this may take some time, so
	// wait a bit for northd to create the cluster router's datapath in southbound
	var datapath string
	err := wait.PollImmediate(time.Second, 30*time.Second, func() (bool, error) {
		datapath, _, _ = RunOVNSbctl("--data=bare", "--no-heading", "--columns=_uuid", "find", "datapath",
			"external_ids:name="+datapathName)
		datapath = strings.TrimSuffix(datapath, "\n")
		// Ignore errors; can't easily detect which are transient or fatal
		return datapath != "", nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to get the datapath UUID of %s from OVN SB "+
			"stdout: %q, error: %v", ovntypes.OVNClusterRouter, datapath, err)
	}
	return datapath, nil
}

// Finds any OVN Load Balancer based on external ID and value
func FindOVNLoadBalancer(externalID, externalValue string) (string, string, error) {
	out, stderr, err := RunOVNNbctl("--data=bare",
		"--no-heading", "--columns=_uuid", "find", "load_balancer",
		"external_ids:"+externalID+"="+externalValue)
	if err != nil {
		return "", stderr, err
	}
	return out, "", nil
}
