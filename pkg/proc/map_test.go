package proc

import (
	"flag"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func Test_ParseProcMaps(t *testing.T) {
	cpkg := getCurrentPkgPath(t)
	flag.Set("host-path", filepath.Join(cpkg, "testdata"))
	flag.Parse()

	tmp, err := os.Create("/tmp/perf-999999.map")
	require.NoErrorf(t, err, "Failed to create temp perf map file")
	defer tmp.Close()
	t.Cleanup(func() { os.Remove(tmp.Name()) })

	fakeProcPath := filepath.Join(cpkg, "/testdata/proc/999999")
	err = os.Symlink(filepath.Join(fakeProcPath, "real_root"), filepath.Join(fakeProcPath, "root"))
	require.NoError(t, err, "Failed to create symlink")
	t.Cleanup(func() { unix.Unlink(filepath.Join(fakeProcPath, "root")) })

	maps, err := ParseProcMaps(999999)
	require.NoError(t, err, "Failed to parse proc map")

	expected := []*Map{
		{
			Pathname:   "/root/server_cc",
			StartAddr:  0x00005574043c5000,
			EndAddr:    0x00005574043c8000,
			FileOffset: 0x00002000,
			DevMajor:   8,
			DevMinor:   1,
			Inode:      3514815,
		},
		{
			Pathname:   "/usr/lib/x86_64-linux-gnu/libc-2.31.so",
			StartAddr:  0x00007f500dc49000,
			EndAddr:    0x00007f500ddc1000,
			FileOffset: 0x22000,
			Inode:      76188,
			DevMajor:   8,
			DevMinor:   1,
		},
		{
			Pathname:   "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
			StartAddr:  0x00007f500de1c000,
			EndAddr:    0x00007f500de2e000,
			FileOffset: 0x3000,
			Inode:      72825,
			DevMajor:   8,
			DevMinor:   1,
		},
		{
			Pathname:   "/usr/lib/x86_64-linux-gnu/libm-2.31.so",
			StartAddr:  0x00007f500de41000,
			EndAddr:    0x00007f500dee8000,
			FileOffset: 0xd000,
			Inode:      76190,
			DevMajor:   8,
			DevMinor:   1,
		},
		{
			Pathname:   "/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.28",
			StartAddr:  0x00007f500e019000,
			EndAddr:    0x00007f500e10a000,
			FileOffset: 0x96000,
			Inode:      66239,
			DevMajor:   8,
			DevMinor:   1,
		},
		{
			Pathname:   "/usr/lib/x86_64-linux-gnu/ld-2.31.so",
			StartAddr:  0x00007f500e176000,
			EndAddr:    0x00007f500e199000,
			FileOffset: 0x1000,
			Inode:      76184,
			DevMajor:   8,
			DevMinor:   1,
		},
		{
			Pathname:  "[vdso]",
			StartAddr: 0x7ffd55b49000,
			EndAddr:   0x7ffd55b4b000,
		},
		{
			Pathname: filepath.Join(fakeProcPath, "real_root/tmp/perf-999999.map"),
		},
		{
			Pathname: "/tmp/perf-999999.map",
		},
	}

	diff := cmp.Diff(expected, maps)
	assert.Emptyf(t, diff, "Diff (-want, +got):\n%s", diff)
}

func getCurrentPkgPath(t *testing.T) string {
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok, "Failed to determine current package path")
	return path.Dir(filename)
}
