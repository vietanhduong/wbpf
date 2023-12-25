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
	compiler   string
	includes   []string
	cflags     []string
	outtyp     OutputType
	targetArch targetArch
	outputDir  string
	outputName string
}

type Option func(*options)

func WithCompiler(cc string) Option {
	return func(o *options) {
		if cc != "" {
			o.compiler = cc
		}
	}
}

// WithInclude add the specified directory to the search path for include files
func WithInclude(include ...string) Option {
	return func(o *options) {
		for _, inc := range include {
			if inc != "" {
				o.includes = append(o.includes, inc)
			}
		}
	}
}

// WithCFlags flags passed to the compiler, may contain quoted arguments.
// These flags are specified will append at the end of the compile arguments.
// That means, if some input flags are dupilicated with the standard flags,
// it will be ignored.
func WithCFlags(cflag ...string) Option {
	return func(o *options) {
		for _, f := range cflag {
			if f != "" {
				o.cflags = append(o.cflags, f)
			}
		}
	}
}

// WithOutputType determine the type of output. If the input type as OutputTypeSource,
// this function will run as -E flag (C-Preprocessor)
// Available options: OutputTypeObject, OutputTypeSource
//
// Default: OutputTypeObject
func WithOutputType(typ OutputType) Option {
	return func(o *options) {
		if typ.IsValid() {
			o.outtyp = typ
		}
	}
}

// WithTargetAch this not actually impact to the outputs format. Instead, this option
// will attach a -D__TARGET_ARCH_<linux_arch> into the compile args.
// If not specified, the compiler will try to resolve the linux arch by runtime.GOARCH
func WithTargetArch(arch string) Option {
	return func(o *options) {
		if arch == "" {
			return
		}
		o.targetArch = targetArch{arch: arch, linux: supportArchs[arch]}
	}
}

// WithOutputDir the output directory. This function will try to create the output directory
// if specified.
// Please note that, the input path should contain only the directory WITHOUT the output filename.
// If you want to specify the output filename, you need to use WithOutputName option.
//
// Default: . (current directory)
func WithOutputDir(path string) Option {
	return func(o *options) { o.outputDir = path }
}

// WithOutputName is the expected (base) filename produced from the source.
func WithOutputName(name string) Option {
	return func(o *options) { o.outputName = name }
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
