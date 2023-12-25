package compiler

import (
	"fmt"
	"runtime"

	"github.com/vietanhduong/wbpf/pkg/cpu"
)

type OutputType string

const (
	OutputTypeObject OutputType = "o"
	OutputTypeSource OutputType = "c"
)

type targetArch struct {
	arch  string
	linux string
}

type options struct {
	compiler    string
	includes    []string
	cflags      []string
	outtyp      OutputType
	targetArch  targetArch
	extraParams []string
	outputDir   string
	outputName  string
}

type Option func(*options)

func WithCompiler(cc string) Option {
	return func(o *options) {
		if cc != "" {
			o.compiler = cc
		}
	}
}

func WithInclude(include ...string) Option {
	return func(o *options) {
		for _, inc := range include {
			if inc != "" {
				o.includes = append(o.includes, inc)
			}
		}
	}
}

func WithCFlags(cflag ...string) Option {
	return func(o *options) {
		for _, f := range cflag {
			if f != "" {
				o.cflags = append(o.cflags, f)
			}
		}
	}
}

func WithOutputType(typ OutputType) Option {
	return func(o *options) {
		if typ.IsValid() {
			o.outtyp = typ
		}
	}
}

func WithTargetArch(arch string) Option {
	return func(o *options) {
		if arch == "" {
			return
		}
		o.targetArch = targetArch{arch: arch, linux: supportArchs[arch]}
	}
}

func WithOutputDir(path string) Option {
	return func(o *options) { o.outputDir = path }
}

func WithOutputName(name string) Option {
	return func(o *options) { o.outputName = name }
}

func WithExtraParam(param ...string) Option {
	return func(o *options) {
		for _, p := range param {
			if p != "" {
				o.extraParams = append(o.extraParams, p)
			}
		}
	}
}

func defaultCflags() []string {
	cpus, err := cpu.PossibleCPUs()
	if err != nil {
		log.WithError(err).Warnf("Failed to get possible CPUs")
	}
	return []string{
		"-O2", "--target=bpf", "-mcpu=v1",
		fmt.Sprintf("-D__NR_CPUS__=%d", len(cpus)),
		"-Wall", "-Werror", "-fpie",
		"-Wno-unused-variable", "-Wno-unused-function",
	}
}

var supportArchs = map[string]string{
	"386":     "x86",
	"amd64":   "x86",
	"arm":     "arm",
	"arm64":   "arm64",
	"ppc64le": "powerpc",
	"riscv64": "riscv",
	"armbe":   "arm",
	"arm64be": "arm64",
	"ppc64":   "powerpc",
	"s390":    "s390",
	"s390x":   "s390",
	"sparc":   "sparc",
	"sparc64": "sparc",
}

func defaultOptions() *options {
	return &options{
		compiler: "clang",
		targetArch: targetArch{
			arch:  runtime.GOARCH,
			linux: supportArchs[runtime.GOARCH],
		},
		outtyp: OutputTypeObject,
	}
}

func (typ OutputType) IsValid() bool {
	switch typ {
	case OutputTypeObject, OutputTypeSource:
		return true
	}
	return false
}
