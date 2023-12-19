package logging

import (
	"flag"

	"github.com/spf13/viper"
)

const (
	namespace          = "log"
	levelFlag          = namespace + ".level"
	formatFlag         = namespace + ".format"
	outputAsStderrFlag = namespace + ".output-as-stderr"
)

func RegisterFlags(fs *flag.FlagSet) {
	opts := defaultLogOpts()
	fs.String(levelFlag, opts.level.String(), "Log level. Available options: panic, fatal, error, info (default), warn (or warning), debug and trace.")
	fs.String(formatFlag, string(opts.format), "Log output format. Available options: text (default), json, json-ts.")
	fs.Bool(outputAsStderrFlag, false, "If enable, the output log will be print as stderr. Otherwise, print logs as stdout.")
}

func SetupLoggingWithViper(v *viper.Viper) {
	opts := []LogOption{
		WithLogFormat(LogFormat(v.GetString(formatFlag))),
		WithLogLevel(v.GetString(levelFlag)),
	}
	if v.GetBool(outputAsStderrFlag) {
		opts = append(opts, WithLogOutputAsStderr())
	}
	SetupLogging(opts...)
}
