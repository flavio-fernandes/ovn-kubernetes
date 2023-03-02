package clustermanager

import (
	"fmt"
	"sync"

	bitmapallocator "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/ipallocator/allocator"
)

// IdAllocator is used to allocate id for a resource and store the resource - id in a map
type IdAllocator struct {
	name      string
	nameIdMap sync.Map
	idBitmap  *bitmapallocator.AllocationBitmap
	sync.Mutex
}

// NewIdAlloctar returns an IdAllocator
func NewIdAlloctar(name string, maxIds int) *IdAllocator {
	idBitmap := bitmapallocator.NewContiguousAllocationMap(maxIds, name)

	// Reserve the 0th bit.
	_, _ = idBitmap.Allocate(0)
	return &IdAllocator{
		name:      name,
		nameIdMap: sync.Map{},
		idBitmap:  idBitmap,
	}
}

// AllocateId allocates an id for the resource 'name' and returns the id.
// If the id for the resource is already allocated, it returns the cached id.
func (idAllocator *IdAllocator) AllocateId(name string) (int, error) {
	idAllocator.Lock()
	defer idAllocator.Unlock()

	// Check the idMap and return the id if its already allocated
	v, ok := idAllocator.nameIdMap.Load(name)
	if ok {
		return v.(int), nil
	}

	id, allocated, _ := idAllocator.idBitmap.AllocateNext()

	if !allocated {
		return -1, fmt.Errorf("failed in allocating the id for the resource %s", name)
	}

	idAllocator.nameIdMap.Store(name, id)
	return id, nil
}

// ReserveId reserves the id 'id' for the resource 'name'. Returns error
// if the 'id' is already reserved.
func (idAllocator *IdAllocator) ReserveId(name string, id int) error {
	idAllocator.Lock()
	defer idAllocator.Unlock()

	reserved, _ := idAllocator.idBitmap.Allocate(id)
	if !reserved {
		return fmt.Errorf("id [%d] is already reserved", id)
	}

	idAllocator.nameIdMap.Store(name, id)
	return nil
}

// ReleaseId releases the id allocated for the resource 'name'
func (idAllocator *IdAllocator) ReleaseId(name string) {
	idAllocator.Lock()
	defer idAllocator.Unlock()

	v, ok := idAllocator.nameIdMap.Load(name)
	if ok {
		idAllocator.idBitmap.Release(v.(int))
	}
}
