package node

import (
	// "fmt"
	"net"
	// "os"
	// "strings"
	"sync"
	"time"

	// "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	// "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube/healthcheck"
	// "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	// "github.com/pkg/errors"
	// kapi "k8s.io/api/core/v1"
	// discovery "k8s.io/api/discovery/v1"
	// ktypes "k8s.io/apimachinery/pkg/types"
	// apierrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	// utilnet "k8s.io/utils/net"
)

type egressIpNodeManager struct {
	nodeName     string
	watchFactory factory.NodeWatchFactory
	addresses    sets.String

	// useNetlink indicates the addressManager should use machine
	// information from netlink. Set to false for testcases.
	useNetlink bool

	sync.Mutex
}

func newEgressIpNodeManager(nodeName string, watchFactory factory.NodeWatchFactory) *egressIpNodeManager {
	return newEgressIpNodeManagerInternal(nodeName, watchFactory, true)
}

func newEgressIpNodeManagerInternal(nodeName string, watchFactory factory.NodeWatchFactory, useNetlink bool) *egressIpNodeManager {
	mgr := &egressIpNodeManager{
		nodeName:     nodeName,
		watchFactory: watchFactory,
		useNetlink:   useNetlink,
	}
	mgr.sync()
	return mgr
}

func (c *egressIpNodeManager) Run(stopChan <-chan struct{}, doneWg *sync.WaitGroup) {
	c.runInternal(stopChan, doneWg)
}

func (c *egressIpNodeManager) sync() {
	var err error
	var addrs []net.Addr
	var interfaces []net.Interface

	if c.useNetlink {
		interfaces, err = net.Interfaces()
		if err != nil {
			klog.Errorf("Failed to sync Node IP Manager: unable list all IPs on the node, error: %v", err)
			return
		}
	}

	currAddresses := sets.NewString()
	for _, interfaceItem := range interfaces {
		addrs, err = interfaceItem.Addrs()
		if err != nil {
			klog.Errorf("Unable list all IPs on the node %s of interface %s, error: %v",
				c.nodeName, interfaceItem.Name, err)
			continue
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				klog.Errorf("Invalid IP address found on host %s interface %s: %s",
					c.nodeName, interfaceItem.Name, addr.String())
				continue
			}
			if !c.isValidNodeIP(ip) {
				klog.V(5).Infof("Skipping non-useable IP address for host: %s interface %s: %s",
					c.nodeName, interfaceItem.Name, ip.String())
				continue
			}
			currAddresses.Insert(ip.String())
		}
	}

	addrChanged := c.assignAddresses(currAddresses)
	if addrChanged {
		klog.Infof("Node address changed to %v.", currAddresses)
	}

	if !c.doesNodeHostAddressesMatch() {
		klog.Infof("Node address does not match with annotation %v", currAddresses)

		// err := c.updateNodeAddressAnnotations()
		// if err != nil {
		// 	klog.Errorf("Address Manager failed to update node address annotations: %v", err)
		// }
	}
}

func (c *egressIpNodeManager) assignAddresses(nodeHostAddresses sets.String) bool {
	c.Lock()
	defer c.Unlock()

	if nodeHostAddresses.Equal(c.addresses) {
		return false
	}
	c.addresses = nodeHostAddresses
	return true
}

func (c *egressIpNodeManager) doesNodeHostAddressesMatch() bool {
	c.Lock()
	defer c.Unlock()

	node, err := c.watchFactory.GetNode(c.nodeName)
	if err != nil {
		klog.Errorf("Unable to get node from informer")
		return false
	}
	// check to see if ips on the node differ from what we stored
	// in host-address annotation
	nodeHostAddresses, err := util.ParseNodeHostAddresses(node)
	if err != nil {
		klog.Errorf("Unable to parse addresses from node host %s: %s", node.Name, err.Error())
		return false
	}

	return nodeHostAddresses.Equal(c.addresses)
}

// runInternal can be used by testcases to provide a fake subscription function
// rather than using netlink
func (c *egressIpNodeManager) runInternal(stopChan <-chan struct{}, doneWg *sync.WaitGroup) {
	nodeInformer := c.watchFactory.NodeInformer()
	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, new interface{}) {
			c.handleNodeChanges(new)
		},
	})

	doneWg.Add(1)
	go func() {
		defer doneWg.Done()

		addressSyncTimer := time.NewTicker(30 * time.Second)
		defer addressSyncTimer.Stop()

		for {
			select {
			case <-addressSyncTimer.C:
				klog.V(5).Info("Node IP manager calling sync() explicitly")
				c.sync()
			case <-stopChan:
				return
			}
		}
	}()

	klog.Info("Egress IP Node is running")
}

// handleNodeChanges takes a node obj, extracts its name and determines if the node's address changed. If so, it
// updates the node's OVS encapsulation IP.
func (c *egressIpNodeManager) handleNodeChanges(obj interface{}) {
	// var err error
	// nodePrimaryAddrChanged, err := c.nodePrimaryAddrChanged()
	// if err != nil {
	// 	klog.Errorf("Address Manager failed to check node primary address change: %v", err)
	// 	return
	// }
	// if nodePrimaryAddrChanged {
	// 	klog.Infof("Node primary address changed to %v. Updating OVN encap IP.", c.nodePrimaryAddr)
	// 	c.updateOVNEncapIPAndReconnect()
	// }
}

// checkSecondaryEgressIPAddresses will reconcile the egressip addresses that need to be added to
// secondary subnets of the node
// func checkSecondaryEgressIPAddresses(nodeName string, wf factory.NodeWatchFactory) {
// 	klog.Infof("Checking Secondary Addresses for node %s", nodeName)

// 	nodeInformer := wf.NodeInformer()
// 	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
// 		UpdateFunc: func(old, new interface{}) {
// 			c.handleNodeChanges(new)
// 		},
// 	})

// 	// node, err := wf.GetNode(nodeName)
// 	// if err != nil {
// 	// 	klog.Errorf("Cannot get node %s: %w", nodeName, err)
// 	// 	return
// 	// }

// }

// detects if the IP is valid for a node
// excludes things like local IPs, mgmt port ip, special masquerade IP
func (c *egressIpNodeManager) isValidNodeIP(addr net.IP) bool {
	if addr == nil {
		return false
	}
	if addr.IsLinkLocalUnicast() {
		return false
	}
	if addr.IsLoopback() {
		return false
	}

	// if utilnet.IsIPv4(addr) {
	// 	if c.mgmtPortConfig.ipv4 != nil && c.mgmtPortConfig.ipv4.ifAddr.IP.Equal(addr) {
	// 		return false
	// 	}
	// } else if utilnet.IsIPv6(addr) {
	// 	if c.mgmtPortConfig.ipv6 != nil && c.mgmtPortConfig.ipv6.ifAddr.IP.Equal(addr) {
	// 		return false
	// 	}
	// }

	if util.IsAddressReservedForInternalUse(addr) {
		return false
	}

	return true
}

// updates the address manager with a new IP
// returns true if there was an update
func (c *egressIpNodeManager) addAddr(ip net.IP) bool {
	c.Lock()
	defer c.Unlock()
	if !c.addresses.Has(ip.String()) && c.isValidNodeIP(ip) {
		klog.Infof("Adding IP: %s, to node IP manager", ip)
		c.addresses.Insert(ip.String())
		return true
	}

	return false
}

// removes IP from address manager
// returns true if there was an update
func (c *egressIpNodeManager) delAddr(ip net.IP) bool {
	c.Lock()
	defer c.Unlock()
	if c.addresses.Has(ip.String()) && c.isValidNodeIP(ip) {
		klog.Infof("Removing IP: %s, from node IP manager", ip)
		c.addresses.Delete(ip.String())
		return true
	}

	return false
}
