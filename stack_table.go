package wbpf

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
)

const MAX_STACK_DEPTH = 127

type stacktrace struct{ insptr [MAX_STACK_DEPTH]uint64 }

func (t *Table) GetStackAddr(stackId int, clear bool) ([]uint64, error) {
	if t.TableType() != ebpf.StackTrace {
		return nil, ErrIncorrectTableType
	}

	if stackId < 0 {
		return nil, nil
	}

	var b []byte
	var err error
	if b, err = t.LookupBytes(uint32(stackId)); len(b) == 0 {
		return nil, fmt.Errorf("lookup key 0x%08x: %w", stackId, err)
	}

	stack := (*stacktrace)(unsafe.Pointer(&b[0]))
	var addrs []uint64
	for i := 0; i < MAX_STACK_DEPTH && stack.insptr[i] != 0; i++ {
		addrs = append(addrs, stack.insptr[i])
	}
	if clear {
		if err := t.Delete(uint32(stackId)); err != nil {
			return nil, fmt.Errorf("delete key 0x%08x: %w", stackId, err)
		}
	}
	return addrs, nil
}
