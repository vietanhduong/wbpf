package wbpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

var (
	ErrTableNotFound      = fmt.Errorf("table not found")
	ErrIncorrectTableType = fmt.Errorf("incorrect table type")
	ErrTableIsNil         = fmt.Errorf("table is nil")
)

type UpdateFlag uint32

const (
	UpdateAny UpdateFlag = iota
	// UpdateNoExist creates a new element.
	UpdateNoExist UpdateFlag = 1 << (iota - 1)
	// UpdateExist updates an existing element.
	UpdateExist
	// UpdateLock updates elements under bpf_spin_lock.
	UpdateLock
)

type Table struct {
	*ebpf.Map
	info *ebpf.MapInfo

	mod *Module
}

func (t *Table) TableType() ebpf.MapType { return t.info.Type }

func (t *Table) TableName() string { return t.info.Name }

func (f UpdateFlag) ToMapUpdateFlag() ebpf.MapUpdateFlags {
	switch f {
	case UpdateNoExist:
		return ebpf.UpdateNoExist
	case UpdateExist:
		return ebpf.UpdateExist
	case UpdateLock:
		return ebpf.UpdateLock
	}
	return ebpf.UpdateAny
}
