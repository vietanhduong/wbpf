package compiler

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/vietanhduong/wbpf/pkg/exec"
	"github.com/vietanhduong/wbpf/pkg/logging"
	"github.com/vietanhduong/wbpf/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithFields(logrus.Fields{logfields.LogSubsys: "compiler"})

func Compile(ctx context.Context, source string, opt ...Option) (string, error) {
	if _, err := os.Stat(source); err != nil {
		return "", fmt.Errorf("os stats %q: %w", source, err)
	}

	opts := defaultOptions()
	for _, o := range opt {
		o(opts)
	}

	if opts.targetArch.linux == "" {
		return "", fmt.Errorf("unable to determine linux arch (%s)", opts.targetArch.arch)
	}

	if opts.outputDir == "" {
		opts.outputDir = "."
	} else {
		_ = os.MkdirAll(opts.outputDir, 0o755)
	}

	if opts.outputName == "" {
		name := filepath.Base(source)
		name = strings.TrimSuffix(name, filepath.Ext(name))

		if opts.outtyp == OutputTypeSource {
			name += "_preprocessor.c"
		} else {
			name += ".o"
		}
		opts.outputName = name
	}

	compiler, err := exec.Which(opts.compiler)
	if err != nil {
		return "", fmt.Errorf("unable to detech location of %s compiler: %w", opts.compiler, err)
	}

	var args []string
	// includes
	for _, inc := range opts.includes {
		args = append(args, fmt.Sprintf("-I%s", inc))
	}

	switch opts.outtyp {
	case OutputTypeObject:
		args = append(args, "-g")
	case OutputTypeSource:
		args = append(args, "-E") // preprocessor
	}

	args = append(args, defaultCflags()...)
	args = append(args, fmt.Sprintf("-D__TARGET_ARCH_%s", opts.targetArch.linux))
	args = append(args, opts.cflags...)
	args = append(args, "-c", source, "-o", "-") // write output to stdout

	log.WithFields(logrus.Fields{
		"arch":     opts.targetArch.linux,
		"compiler": compiler,
		"args":     args,
	}).Debug("launching compiler")

	cmd, cancel := exec.WithCancel(ctx, compiler, args...)
	defer cancel()

	output, err := os.Create(filepath.Join(opts.outputDir, opts.outputName))
	if err != nil {
		return "", fmt.Errorf("os create %s: %w", filepath.Join(opts.outputDir, opts.outputName), err)
	}
	defer output.Close()

	cmd.Stdout = output
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err = cmd.Run()

	var maxrss int64 // maximum resident set size (unit: byte)
	if cmd.ProcessState != nil {
		if usage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
			maxrss = usage.Maxrss
		}
	}

	if err != nil {
		err = fmt.Errorf("failed to compile %s: %w", opts.outputName, err)

		if !errors.Is(err, context.Canceled) {
			var pid int = -1
			if cmd.Process != nil {
				pid = cmd.Process.Pid
			}
			log.WithFields(logrus.Fields{
				logfields.PID: pid,
				"maxrss":      fmt.Sprintf("%d (byte)", maxrss),
			}).Error(err)
		}
		scanner := bufio.NewScanner(io.LimitReader(&stderr, 1_000_000))
		for scanner.Scan() {
			log.Warn(scanner.Text())
		}
		return "", err
	}

	if maxrss > 0 {
		log.WithFields(logrus.Fields{
			logfields.PID: cmd.Process.Pid,
			"output":      output.Name(),
		}).Debugf("Compilation had peak RSS of %d bytes", maxrss)
	}

	return output.Name(), nil
}
