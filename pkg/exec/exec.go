package exec

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vietanhduong/wbpf/pkg/logging"
	"github.com/vietanhduong/wbpf/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithFields(logrus.Fields{logfields.LogSubsys: "exec"})

func warnToLog(cmd *exec.Cmd, out []byte, err error) {
	log.WithError(err).WithField("cmd", cmd.Args).Error("Command execution failed")
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		log.Warn(scanner.Text())
	}
}

// combinedOutput is the core implementation of catching deadline exceeded
// options and logging errors.
func combinedOutput(ctx context.Context, cmd *exec.Cmd, verbose bool) ([]byte, error) {
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		if !errors.Is(ctx.Err(), context.Canceled) {
			log.WithError(err).WithField("cmd", cmd.Args).Error("Command execution failed")
		}
		return nil, fmt.Errorf("command execution failed for %s: %w", cmd.Args, ctx.Err())
	}
	if err != nil && verbose {
		warnToLog(cmd, out, err)
	}
	return out, err
}

// output is the equivalent to combinedOutput with only capturing stdout
func output(ctx context.Context, cmd *exec.Cmd, verbose bool) ([]byte, error) {
	out, err := cmd.Output()
	if ctx.Err() != nil {
		if !errors.Is(ctx.Err(), context.Canceled) {
			log.WithError(err).WithField("cmd", cmd.Args).Error("Command execution failed")
		}
		return nil, fmt.Errorf("command execution failed for %s: %w", cmd.Args, ctx.Err())
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			err = fmt.Errorf("%w stderr=%q", exitErr, exitErr.Stderr)
		}
		if verbose {
			warnToLog(cmd, out, err)
		}
	}
	return out, err
}

// Cmd wraps exec.Cmd with a context to provide convenient execution of a
// command with nice checking of the context timeout in the form:
//
// err := exec.Prog().WithTimeout(5*time.Second, myprog, myargs...).CombinedOutput(log, verbose)
type Cmd struct {
	*exec.Cmd
	ctx      context.Context
	cancelFn func()
}

// CommandContext wraps exec.CommandContext to allow this package to be used as
// a drop-in replacement for the standard exec library.
func CommandContext(ctx context.Context, prog string, args ...string) *Cmd {
	return &Cmd{
		Cmd: exec.CommandContext(ctx, prog, args...),
		ctx: ctx,
	}
}

// WithTimeout creates a Cmd with a context that times out after the specified
// duration.
func WithTimeout(timeout time.Duration, prog string, args ...string) *Cmd {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	cmd := CommandContext(ctx, prog, args...)
	cmd.cancelFn = cancel
	return cmd
}

// WithCancel creates a Cmd with a context that can be cancelled by calling the
// resulting Cancel() function.
func WithCancel(ctx context.Context, prog string, args ...string) (*Cmd, context.CancelFunc) {
	newCtx, cancel := context.WithCancel(ctx)
	cmd := CommandContext(newCtx, prog, args...)
	return cmd, cancel
}

// CombinedOutput runs the command and returns its combined standard output and
// standard error. Unlike the standard library, if the context is exceeded, it
// will return an error indicating so.
//
// Logs any errors that occur to the specified logger.
func (c *Cmd) CombinedOutput(verbose bool) ([]byte, error) {
	out, err := combinedOutput(c.ctx, c.Cmd, verbose)
	if c.cancelFn != nil {
		c.cancelFn()
	}
	return out, err
}

// Output runs the command and returns only standard output, but not the
// standard error. Unlike the standard library, if the context is exceeded,
// it will return an error indicating so.
//
// Logs any errors that occur to the specified logger.
func (c *Cmd) Output(scopedLog *logrus.Entry, verbose bool) ([]byte, error) {
	out, err := output(c.ctx, c.Cmd, verbose)
	if c.cancelFn != nil {
		c.cancelFn()
	}
	return out, err
}

func Which(bin string) (string, error) {
	cmd := WithTimeout(time.Second, "which", bin)
	out, err := cmd.CombinedOutput(true)
	if err != nil {
		return "", fmt.Errorf("%s not found", bin)
	}
	return strings.TrimSpace(string(out)), nil
}
