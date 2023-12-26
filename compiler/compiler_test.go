package compiler

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vietanhduong/wbpf"
)

func Test_Compile(t *testing.T) {
	t.Cleanup(func() { os.RemoveAll("/tmp/wbpf-test") })

	testcases := []struct {
		name string
		opts []Option
		src  string
	}{
		{
			name: "TEST SUCCESS: test compile kprobe",
			opts: []Option{
				WithCompiler(os.Getenv("TEST_CC")),
				WithInclude("../examples/headers/vmlinux"),
				WithInclude("../examples/headers/libbpf"),
				WithOutputDir("/tmp/wbpf-test"),
				WithOutputName("kprobe.o"),
			},
			src: "../examples/kprobe/kprobe.bpf.c",
		},
		{
			name: "TEST SUCCESS: test compile profiler",
			opts: []Option{
				WithCompiler(os.Getenv("TEST_CC")),
				WithInclude("../examples/headers/vmlinux"),
				WithInclude("../examples/headers/libbpf"),
				WithOutputDir("/tmp/wbpf-test"),
				WithOutputName("profiler.o"),
			},
			src: "../examples/profiler/profiler.bpf.c",
		},
		{
			name: "TEST SUCCESS: test compile uprobe",
			opts: []Option{
				WithCompiler(os.Getenv("TEST_CC")),
				WithInclude("../examples/headers/vmlinux"),
				WithInclude("../examples/headers/libbpf"),
				WithOutputDir("/tmp/wbpf-test"),
				WithOutputName("uprobe.o"),
			},
			src: "../examples/uprobe/uprobe.bpf.c",
		},
		{
			name: "TEST SUCCESS: test compile xdp",
			opts: []Option{
				WithCompiler(os.Getenv("TEST_CC")),
				WithInclude("../examples/headers/vmlinux"),
				WithInclude("../examples/headers/libbpf"),
				WithOutputDir("/tmp/wbpf-test"),
				WithOutputName("xdp.o"),
			},
			src: "../examples/xdp/xdp.bpf.c",
		},
	}
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			output, err := Compile(context.Background(), tt.src, tt.opts...)
			t.Cleanup(func() { os.RemoveAll(output) })
			require.NoError(t, err)
			info, err := os.Stat(output)
			require.NoError(t, err)
			require.Nil(t, err)
			require.False(t, info.IsDir())
			require.NotZero(t, info.Size())

			mod, err := wbpf.NewModule(wbpf.WithElfFile(output))
			require.NoError(t, err, "Failed to new wbpf module")
			mod.Close()
		})
	}
}
