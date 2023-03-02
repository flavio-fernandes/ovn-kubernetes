package subnetallocator

import (
	"net"
)

type ZoneSubnetAllocator struct {
	namedSubnetAllocator
}

func NewZoneSubnetAllocator() *ZoneSubnetAllocator {
	return &ZoneSubnetAllocator{
		namedSubnetAllocator: namedSubnetAllocator{
			name:              "Zone",
			base:              NewSubnetAllocator(),
			recordSubnetUsage: nil,
			recordSubnetCount: nil,
		},
	}
}

// ZoneSubnetAllocator either validates existing zone subnets against the allocators
// ranges, or allocates new subnets if the zone doesn't have any yet, or returns an error
func (sna *ZoneSubnetAllocator) AllocateZoneSubnets(zone string, existingSubnets []*net.IPNet, ipv4Mode, ipv6Mode bool) ([]*net.IPNet, []*net.IPNet, error) {
	return sna.allocateOwnerSubnets(zone, existingSubnets, ipv4Mode, ipv6Mode)
}

func (sna *ZoneSubnetAllocator) ReleaseZoneSubnets(zone string, subnets ...*net.IPNet) error {
	return sna.releaseOwnerSubnets(zone, subnets...)
}

func (sna *ZoneSubnetAllocator) ReleaseAllZoneSubnets(zone string) {
	sna.releaseAllOwnerSubnets(zone)
}

func (sna *ZoneSubnetAllocator) GetZoneSubnets(zone string) []*net.IPNet {
	return sna.getAllOwnerSubnets(zone)
}
