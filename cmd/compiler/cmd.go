package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/vietanhduong/wbpf/compiler"
	"github.com/vietanhduong/wbpf/pkg/logging"
	"github.com/vietanhduong/wbpf/pkg/logging/logfields"
)

func newCommand() *cobra.Command {
	var (
		cc         string
		includes   []string
		cflags     []string
		target     string
		outputType string
		outputPath string
		logLevel   string
		logFormat  string
	)

	this := &cobra.Command{
		Use:   "compiler [source]",
		Short: "eBPF compiler which is used to compile the input source to C-Preprocessor or Object file.",
		Long: `
eBPF compiler which is used to compile the input source to C-Preprocessor or Object file.
To do this, eBPF compile require a compiler tool like 'clang'. You also change the compiler
via the $CC environment variable.
		`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pflag := cmd.Flags()
			args := pflag.Args()
			if pflag.ArgsLenAtDash() != -1 {
				cflags = pflag.Args()[pflag.ArgsLenAtDash():]
				args = pflag.Args()[:pflag.ArgsLenAtDash()]
			}

			if len(args) != 1 || len(args[0]) == 0 {
				return fmt.Errorf("source file is required")
			}
			if outputType != "o" && outputType != "c" {
				return fmt.Errorf("invalid --output-type")
			}

			lopts := []logging.LogOption{
				logging.WithLogLevel(logLevel),
			}

			if strings.EqualFold(logFormat, "json") {
				lopts = append(lopts, logging.WithJsonFormat())
			}

			logging.SetupLogging(lopts...)

			log := logging.DefaultLogger.WithField(logfields.LogComponent, "cmd")

			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
			defer cancel()

			copts := []compiler.Option{
				compiler.WithCompiler(cc),
				compiler.WithCFlags(cflags...),
				compiler.WithInclude(includes...),
				compiler.WithTargetArch(target),
			}

			if outputPath != "" {
				copts = append(copts, compiler.WithOutputDir(filepath.Dir(outputPath)))
				copts = append(copts, compiler.WithOutputName(filepath.Base(outputPath)))
			}

			if outputType == "c" {
				copts = append(copts, compiler.WithOutputType(compiler.OutputTypeSource))
			}

			output, err := compiler.Compile(ctx, args[0], copts...)
			if err != nil {
				return err
			}
			log.Infof("Output: %s", output)
			return nil
		},
	}

	this.Flags().StringVarP(&cc, "compiler", "C", env("CC", "clang"), "The `binary` used to compile C to BPF.")
	this.Flags().StringArrayVarP(&includes, "include", "I", strings.Split(env("INCLUDES", ""), ","), "The specified directory to the search path for include files.")
	this.Flags().StringVar(&outputType, "output-type", "o", "The type of output file. If the input as 'c', the output will have format as C-Preprocessor file, 'o' stand for object file. Must be one of 'c' or 'o'.")
	this.Flags().StringVarP(&target, "target", "t", "", "The output target arch. If empty, the compiler will try to determine the current linux arch by go arch.")
	this.Flags().StringVarP(&outputPath, "output", "o", env("OUTPUT", ""), "The output file path. Leave empty for create a file in current directory and the file name will be the name of source file.")
	this.Flags().StringVarP(&logLevel, "log-level", "L", env("LOG_LEVEL", "info"), "Log level.")
	this.Flags().StringVar(&logFormat, "log-format", env("LOG_FORMAT", "text"), "Log format. Must be 'json' or 'text'.")

	return this
}

func env(key string, defval string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defval
}
