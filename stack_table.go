package wbpf

import (
	"unsafe"

	"github.com/cilium/ebpf"
)

const MAX_STACK_DEPTH = 127

type StackTraceT struct {
	InsPtr [MAX_STACK_DEPTH]uint64
}

type StackTable struct{ *Table }

func NewStackTable(tbl *Table) (*StackTable, error) {
	if tbl == nil {
		return nil, ErrTableIsNil
	}
	if tbl.TableType() != ebpf.StackTrace {
		return nil, ErrIncorrectTableType
	}
	return &StackTable{tbl}, nil
}

func (t *StackTable) GetStackAddr(stackid int64, clear bool) []uint64 {
	if stackid < 0 {
		return nil
	}

	id := uint32(stackid)

	var b []byte
	if b, _ = t.LookupBytes(id); len(b) == 0 {
		log.Tracef("Failed to lookup key 0x%08x", stackid)
		return nil
	}

	stack := (*StackTraceT)(unsafe.Pointer(&b[0]))

	var addrs []uint64
	for i := 0; i < MAX_STACK_DEPTH && stack.InsPtr[i] != 0; i++ {
		addrs = append(addrs, stack.InsPtr[i])
	}

	if clear {
		if err := t.Delete(id); err != nil {
			log.Tracef("Failed to delete key 0x%08x: %v", stackid, err)
			return nil
		}
	}
	return addrs
}

func (t *StackTable) ClearStackId(stackid int64) {
	if stackid < 0 {
		return
	}
	if err := t.Delete(uint32(stackid)); err != nil {
		log.Tracef("Failed to delete key 0x%08x: %v", stackid, err)
	}
}

func (t *StackTable) GetAddrSymbol(pid int, addr uint64, opts ResolveSymbolOptions) string {
	if pid < 0 {
		return t.mod.ResolveKernelSymbol(addr, opts)
	}
	return t.mod.ResolveSymbol(pid, addr, opts)
}

func (st *StackTraceT) ToBytes() []byte {
	if st == nil {
		return nil
	}
	// Get the size of the struct
	size := unsafe.Sizeof(StackTraceT{})

	// Create a byte slice with the same size as the struct
	b := make([]byte, size)

	// Create an unsafe pointer to the struct
	ptr := unsafe.Pointer(st)

	// Use a loop to copy the bytes from the struct to the byte slice
	for i := 0; i < int(size); i++ {
		b[i] = *(*byte)(unsafe.Pointer(uintptr(ptr) + uintptr(i)))
	}
	return b
}
