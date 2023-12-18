package wbpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

var (
	ErrTableNotFound      = fmt.Errorf("table not found")
	ErrIncorrectTableType = fmt.Errorf("incorrect table type")
)

type Table struct {
	*ebpf.Map
	info *ebpf.MapInfo

	mod *Module
}

func (t *Table) TableType() ebpf.MapType { return t.info.Type }

func (t *Table) TableName() string { return t.info.Name }
