package subnetallocator

import (
	"fmt"
	"net"
	"sync"

	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
)

type recordSubnetUsageFn func(v4SubnetsAllocated, v6SubnetsAllocated float64)
type recordSubnetCountFn func(v4SubnetsAllocated, v6SubnetsAllocated float64)

type namedSubnetAllocator struct {
	name string
	sync.Mutex
	// Don't inherit from BaseSubnetAllocator to ensure users of
	// namedSubnetAllocator can't directly call the underlying methods
	base SubnetAllocator

	recordSubnetUsage recordSubnetUsageFn
	recordSubnetCount recordSubnetCountFn
}

func (sna *namedSubnetAllocator) InitRanges(subnets []config.CIDRNetworkEntry) error {
	for _, entry := range subnets {
		if err := sna.base.AddNetworkRange(entry.CIDR, entry.HostSubnetLength); err != nil {
			return err
		}
		klog.V(5).Infof("Added network range %s to %s subnet allocator", entry.CIDR, sna.name)
	}

	if sna.recordSubnetCount != nil {
		// update metrics for subnets
		v4count, _, v6count, _ := sna.base.Usage()
		sna.recordSubnetCount(float64(v4count), float64(v6count))
	}
	return nil
}

// MarkSubnetsAllocated will mark the given subnets as already allocated by
// the given owner. Marking is all-or-nothing; if marking one of the subnets
// fails then none of them are marked as allocated.
func (sna *namedSubnetAllocator) MarkSubnetsAllocated(owner string, subnets ...*net.IPNet) error {
	if err := sna.base.MarkAllocatedNetworks(owner, subnets...); err != nil {
		return err
	}
	if sna.recordSubnetUsage != nil {
		// update metrics for subnets
		v4count, _, v6count, _ := sna.base.Usage()
		sna.recordSubnetUsage(float64(v4count), float64(v6count))
	}
	return nil
}

// allocateOwnerSubnets either validates existing owner subnets against the allocators
// ranges, or allocates new subnets if the owner doesn't have any yet, or returns an error
func (sna *namedSubnetAllocator) allocateOwnerSubnets(owner string, existingSubnets []*net.IPNet, ipv4Mode, ipv6Mode bool) ([]*net.IPNet, []*net.IPNet, error) {
	allocatedSubnets := []*net.IPNet{}

	// OVN can work in single-stack or dual-stack only.
	expectedHostSubnets := 1
	// if dual-stack mode we expect one subnet per each IP family
	if ipv4Mode && ipv6Mode {
		expectedHostSubnets = 2
	}

	klog.Infof("Expected %d subnets on %s %s, found %d: %v", expectedHostSubnets, sna.name, owner, len(existingSubnets), existingSubnets)

	// If any existing subnets the owner has are valid, mark them as reserved.
	// The owner might have invalid or already-reserved subnets, or it might
	// have more subnets than configured in OVN (like for dual-stack to/from
	// single-stack conversion).
	// filter in place slice
	// https://github.com/golang/go/wiki/SliceTricks#filter-in-place
	foundIPv4 := false
	foundIPv6 := false
	n := 0
	for _, subnet := range existingSubnets {
		if (ipv4Mode && utilnet.IsIPv4CIDR(subnet) && !foundIPv4) || (ipv6Mode && utilnet.IsIPv6CIDR(subnet) && !foundIPv6) {
			if err := sna.MarkSubnetsAllocated(owner, subnet); err == nil {
				klog.Infof("Valid subnet %v allocated on %s %s", subnet, sna.name, owner)
				existingSubnets[n] = subnet
				n++
				if utilnet.IsIPv4CIDR(subnet) {
					foundIPv4 = true
				} else if utilnet.IsIPv6CIDR(subnet) {
					foundIPv6 = true
				}
				continue
			}
		}
		// this subnet is no longer needed; release it
		klog.Infof("Releasing unused or invalid subnet %v on %s %s", subnet, sna.name, owner)
		if err := sna.base.ReleaseNetworks(owner, subnet); err != nil {
			klog.Warningf("Failed to release subnet %v on %s %s: %v", subnet, sna.name, owner, err)
		}
	}
	// recreate existingSubnets with the valid subnets
	existingSubnets = existingSubnets[:n]

	// Node has enough valid subnets already allocated
	if len(existingSubnets) == expectedHostSubnets {
		klog.Infof("Allowed existing subnets %v on %s %s", existingSubnets, sna.name, owner)
		return existingSubnets, allocatedSubnets, nil
	}

	// Release allocated subnets on error
	releaseAllocatedSubnets := true
	defer func() {
		if releaseAllocatedSubnets {
			for _, subnet := range allocatedSubnets {
				klog.Warningf("Releasing subnet %v on %s %s", subnet, sna.name, owner)
				if errR := sna.base.ReleaseNetworks(owner, subnet); errR != nil {
					klog.Warningf("Error releasing subnet %v on %s %s: %v", subnet, sna.name, owner, errR)
				}
			}
		}
	}()

	// allocateOneSubnet is a helper to process the result of a subnet allocation
	allocateOneSubnet := func(allocatedHostSubnet *net.IPNet, allocErr error) error {
		if allocErr != nil {
			return fmt.Errorf("error allocating network for %s %s: %v", sna.name, owner, allocErr)
		}
		// the allocator returns nil if it can't provide a subnet
		// we should filter them out or they will be appended to the slice
		if allocatedHostSubnet != nil {
			klog.V(5).Infof("Allocating subnet %v on %s %s", allocatedHostSubnet, sna.name, owner)
			allocatedSubnets = append(allocatedSubnets, allocatedHostSubnet)
		}
		return nil
	}

	// allocate new subnets if needed
	if ipv4Mode && !foundIPv4 {
		if err := allocateOneSubnet(sna.base.AllocateIPv4Network(owner)); err != nil {
			return nil, nil, err
		}
	}
	if ipv6Mode && !foundIPv6 {
		if err := allocateOneSubnet(sna.base.AllocateIPv6Network(owner)); err != nil {
			return nil, nil, err
		}
	}

	// check if we were able to allocate the new subnets require
	// this can only happen if OVN is not configured correctly
	// so it will require a reconfiguration and restart.
	wantedSubnets := expectedHostSubnets - len(existingSubnets)
	if wantedSubnets > 0 && len(allocatedSubnets) != wantedSubnets {
		return nil, nil, fmt.Errorf("error allocating networks for %s %s: %d subnets expected only new %d subnets allocated",
			sna.name, owner, expectedHostSubnets, len(allocatedSubnets))
	}

	if sna.recordSubnetUsage != nil {
		v4count, _, v6count, _ := sna.base.Usage()
		sna.recordSubnetUsage(float64(v4count), float64(v6count))
	}

	hostSubnets := append(existingSubnets, allocatedSubnets...)
	klog.Infof("Allocated Subnets %v on %s %s", hostSubnets, sna.name, owner)

	// Success; prevent the release-on-error from triggering and return all node subnets
	releaseAllocatedSubnets = false
	return hostSubnets, allocatedSubnets, nil
}

func (sna *namedSubnetAllocator) releaseOwnerSubnets(owner string, subnets ...*net.IPNet) error {
	err := sna.base.ReleaseNetworks(owner, subnets...)
	if sna.recordSubnetUsage != nil {
		v4count, _, v6count, _ := sna.base.Usage()
		sna.recordSubnetUsage(float64(v4count), float64(v6count))
	}
	return err
}

func (sna *namedSubnetAllocator) releaseAllOwnerSubnets(owner string) {
	sna.base.ReleaseAllNetworks(owner)
	if sna.recordSubnetUsage != nil {
		v4count, _, v6count, _ := sna.base.Usage()
		sna.recordSubnetUsage(float64(v4count), float64(v6count))
	}
}

func (sna *namedSubnetAllocator) getAllOwnerSubnets(owner string) []*net.IPNet {
	return sna.base.GetAllOwnerNetworks(owner)
}
