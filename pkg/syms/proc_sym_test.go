package syms

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestProcSym_Resolve(t *testing.T) {
	resolver, err := NewProcSymbol(unix.Getpid(), nil)
	require.NoError(t, err, "Failed to new proc symbol resoler")
	defer resolver.Cleanup()

	resolver.Refresh()
	res := resolver.Resolve(getMallocAddr())
	require.Contains(t, res.Name, "malloc")
	if !strings.Contains(res.Module, "/libc.so") && !strings.Contains(res.Module, "/libc-") {
		t.Errorf("expected libc, got %v", res.Module)
	}
}
