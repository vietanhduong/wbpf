package wbpf

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArrayTable(t *testing.T) {
	tbl, err := NewArrayTable[netip.Addr](createArray(t))
	require.NoError(t, err, "Failed to new array table: %v", err)

	addr, err := netip.ParseAddr("127.0.0.1")

	t.Run("TEST SUCCESS: set value as netip.Addr", func(t *testing.T) {
		require.NoError(t, err, "Failed to parse addr: %v", err)
		err = tbl.Set(0, addr, UpdateAny)
		require.NoError(t, err, "Failed to update value: %v", err)
	})

	t.Run("TEST SUCCESS: get value as netip.Addr", func(t *testing.T) {
		var actual netip.Addr
		err = tbl.Get(0, &actual)
		require.NoError(t, err, "Failed to ret value at index 0: %v", err)
		assert.Equal(t, addr.String(), actual.String())
	})

	t.Run("TEST FAILURE: index out bound", func(t *testing.T) {
		var zero netip.Addr
		err = tbl.Get(2, &zero)
		require.Error(t, err, "No error raised")
		assert.ErrorContains(t, err, "key does not exis", "Incorrect error")
	})
}

func createArray(t *testing.T) *Table {
	t.Helper()

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
	})
	if err != nil {
		require.NoError(t, err, "Failed to new array map: %v", err)
	}
	t.Cleanup(func() { m.Close() })

	return &Table{
		Map: m,
		info: &ebpf.MapInfo{
			Type:       ebpf.Array,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 2,
		},
	}
}
