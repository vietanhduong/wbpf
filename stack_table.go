package wbpf

import (
	"unsafe"

	"github.com/cilium/ebpf"
)

const MAX_STACK_DEPTH = 127

type stacktrace struct{ insptr [MAX_STACK_DEPTH]uint64 }

func (t *Table) GetStackAddr(stackid uint64, clear bool) []uint64 {
	if t.TableType() != ebpf.StackTrace {
		log.Tracef("Incorrect table type (expect: %s, got: %s)", ebpf.StackTrace, t.info.Type)
		return nil
	}

	id := uint32(stackid)
	var b []byte
	if b, _ = t.LookupBytes(id); len(b) == 0 {
		log.Tracef("Failed to lookup key 0x%08x", stackid)
		return nil
	}

	stack := (*stacktrace)(unsafe.Pointer(&b[0]))
	var addrs []uint64
	for i := 0; i < MAX_STACK_DEPTH && stack.insptr[i] != 0; i++ {
		addrs = append(addrs, stack.insptr[i])
	}
	if clear {
		if err := t.Delete(id); err != nil {
			log.Tracef("Failed to delete key 0x%08x: %v", stackid, err)
			return nil
		}
	}
	return addrs
}
