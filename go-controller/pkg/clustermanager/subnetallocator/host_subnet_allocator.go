package subnetallocator

import (
	"net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
)

type HostSubnetAllocator struct {
	namedSubnetAllocator
}

func NewHostSubnetAllocator() *HostSubnetAllocator {
	return &HostSubnetAllocator{
		namedSubnetAllocator: namedSubnetAllocator{
			name:              "Node",
			base:              NewSubnetAllocator(),
			recordSubnetUsage: metrics.RecordSubnetUsage,
			recordSubnetCount: metrics.RecordSubnetCount,
		},
	}
}

// AllocateNodeSubnets either validates existing node subnets against the allocators
// ranges, or allocates new subnets if the node doesn't have any yet, or returns an error
func (sna *HostSubnetAllocator) AllocateNodeSubnets(nodeName string, existingSubnets []*net.IPNet, ipv4Mode, ipv6Mode bool) ([]*net.IPNet, []*net.IPNet, error) {
	return sna.allocateOwnerSubnets(nodeName, existingSubnets, ipv4Mode, ipv6Mode)
}

func (sna *HostSubnetAllocator) ReleaseNodeSubnets(nodeName string, subnets ...*net.IPNet) error {
	return sna.releaseOwnerSubnets(nodeName, subnets...)
}

func (sna *HostSubnetAllocator) ReleaseAllNodeSubnets(nodeName string) {
	sna.releaseAllOwnerSubnets(nodeName)
}
