package elf

import (
	"testing"

	"github.com/ianlancetaylor/demangle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestName(t *testing.T) {
	name := NewName(0xef, 1)
	require.Equal(t, uint32(0xef), name.NameIndex())
	require.Equal(t, SectionLinkIndex(1), name.LinkIndex())
}

func Test_SymbolTable(t *testing.T) {
	testcases := []struct {
		name  string
		fpath string
		size  int
		addrs []struct {
			addr   uint64
			symbol string
		}
	}{
		{
			name:  "test with elf file",
			fpath: "./testdata/elfs/elf",
			addrs: []struct {
				addr   uint64
				symbol string
			}{
				{0x00001149, "iter"},
				{0x0000115e, "main"},
			},
			size: 9,
		},
		{
			name:  "test with go20 file",
			fpath: "./testdata/elfs/go20",
			addrs: []struct {
				addr   uint64
				symbol string
			}{
				{0x004817a0, "main.main"},
			},
			size: 1448,
		},
		{
			name:  "test with SO file",
			fpath: "./testdata/elfs/libexample.so",
			addrs: []struct {
				addr   uint64
				symbol string
			}{
				{0x00001139, "lib_iter"},
			},
			size: 8,
		},
	}
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			e, err := NewMMapedElfFile(tt.fpath)
			require.NoError(t, err, "Failed to new mmaped elf file")
			t.Cleanup(func() { e.Close() })
			symtbl, err := e.NewSymbolTable(&SymbolOptions{DemangleOpts: []demangle.Option{demangle.NoClones}})
			require.NoError(t, err, "Failed to new symbol table")
			t.Cleanup(func() { symtbl.Cleanup() })
			assert.Equal(t, tt.size, symtbl.Size(), "Table size incorrect")
			for _, expected := range tt.addrs {
				assert.Equal(t, expected.symbol, symtbl.Resolve(expected.addr))
			}
		})
	}
}
