package logging

import (
	"io"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

type LogFormat string

const (
	LogFormatJson   LogFormat = "json"
	LogFormatJsonTs LogFormat = "json-ts"
	LogFormatText   LogFormat = "text"
)

type LogOutput string

const (
	LogOutputStdout LogOutput = "stdout"
	LogOutputStderr LogOutput = "stderr"
)

type LogOptions struct {
	format LogFormat
	level  logrus.Level
	output LogOutput
}

type LogOption func(*LogOptions)

func WithJsonFormat() LogOption {
	return func(lo *LogOptions) { lo.format = LogFormatJson }
}

func WithTextFormat() LogOption {
	return func(lo *LogOptions) { lo.format = LogFormatText }
}

func WithJsonTsFormat() LogOption {
	return func(lo *LogOptions) { lo.format = LogFormatJsonTs }
}

func WithLogFormat(format LogFormat) LogOption {
	switch format {
	case LogFormatText, LogFormatJson, LogFormatJsonTs:
	default: // fallback option, in case the input format is invalid
		format = LogFormatText
	}
	return func(lo *LogOptions) { lo.format = format }
}

func WithLogLevel(level string) LogOption {
	return func(lo *LogOptions) { lo.level = parseLogLevel(level) }
}

func WithLogOutputAsStderr() LogOption {
	return func(lo *LogOptions) { lo.output = LogOutputStderr }
}

func defaultLogOpts() *LogOptions {
	return &LogOptions{
		format: LogFormatText,
		level:  logrus.InfoLevel,
		output: LogOutputStdout,
	}
}

func (lf LogFormat) LogrusFormat() logrus.Formatter {
	switch lf {
	case LogFormatJson:
		return &logrus.JSONFormatter{
			DisableTimestamp: true,
			CallerPrettyfier: prettier,
		}
	case LogFormatJsonTs:
		return &logrus.JSONFormatter{
			DisableTimestamp: false,
			TimestampFormat:  time.RFC3339Nano,
			CallerPrettyfier: prettier,
		}
	}
	return &logrus.TextFormatter{
		DisableTimestamp: true,
		DisableColors:    true,
		CallerPrettyfier: prettier,
	}
}

func (lo LogOutput) Writer() io.Writer {
	if lo == LogOutputStderr {
		return os.Stderr
	}
	return os.Stdout
}
