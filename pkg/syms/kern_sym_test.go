package syms

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKernSym_Resolve(t *testing.T) {
	resolver := &KernSym{path: "./testdata/kallsyms"}
	resolver.Refresh()
	require.True(t, len(resolver.symbols) > 0, "Load Kernel Symbols failed")

	testcases := []struct {
		addr uint64
		name string
		mod  string
	}{
		{0xffffffffc035f2e0, "autofs_dev_ioctl_ismountpoint", "autofs4"},
		{0xffffffffc037ee4c, "bpf_prog_6deef7357e7b4530", "bpf"},
		{0xffffffffb5000075, "secondary_startup_64_no_verify", "kernel"},
		{0x0000000000000000, "", ""},
	}
	for _, tt := range testcases {
		sym := resolver.Resolve(tt.addr)
		assert.Equal(t, tt.name, sym.Name)
		assert.Equal(t, tt.mod, sym.Module)
	}
}
