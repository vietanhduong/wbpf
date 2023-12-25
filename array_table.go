package wbpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type ArrayTable[T any] struct{ *Table }

func NewArrayTable[T any](tbl *Table) (*ArrayTable[T], error) {
	if tbl == nil {
		return nil, ErrTableIsNil
	}
	if tbl.TableType() != ebpf.Array {
		return nil, ErrIncorrectTableType
	}

	return &ArrayTable[T]{tbl}, nil
}

func (t *ArrayTable[T]) Get(idx uint32, out *T) error {
	if err := t.Table.Lookup(&idx, out); err != nil {
		return fmt.Errorf("table lookup: %w", err)
	}
	return nil
}

func (t *ArrayTable[T]) Set(idx uint32, val T, flag UpdateFlag) error {
	if err := t.Table.Update(&idx, &val, flag.ToMapUpdateFlag()); err != nil {
		return fmt.Errorf("table update: %w", err)
	}
	return nil
}
