package logging

import (
	"os"

	"github.com/sirupsen/logrus"
)

const (
	Syslog = "syslog"
)

var DefaultLogger = initDefaultLogger()

func initDefaultLogger() *logrus.Logger {
	opts := defaultLogOpts()
	logger := logrus.New()
	logger.SetLevel(opts.level)
	logger.SetReportCaller(true)
	logger.SetFormatter(opts.format.LogrusFormat())
	return logger
}

func SetLogLevel(logLevel logrus.Level) {
	DefaultLogger.SetLevel(logLevel)
}

func SetLogLevelToDebug() {
	DefaultLogger.SetLevel(logrus.DebugLevel)
}

func SetLogFormat(format LogFormat) {
	DefaultLogger.SetFormatter(format.LogrusFormat())
}

func AddHooks(hooks ...logrus.Hook) {
	for _, hook := range hooks {
		DefaultLogger.AddHook(hook)
	}
}

func SetupLogging(logOpts ...LogOption) {
	opts := defaultLogOpts()
	for _, opt := range logOpts {
		opt(opts)
	}

	SetLogFormat(opts.format)
	logrus.SetOutput(os.Stdout)
	SetLogLevel(opts.level)

	logrus.SetLevel(logrus.PanicLevel)
}
