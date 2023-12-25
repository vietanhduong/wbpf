package exec

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	timeout = 250 * time.Millisecond
)

func Test_WithTimeout(t *testing.T) {
	cmd := WithTimeout(timeout, "sleep", "inf")
	require.NoError(t, cmd.Start(), "Failed to start command")
	assert.ErrorContains(t, cmd.Wait(), "signal: killed")
}

func Test_WithCancel(t *testing.T) {
	cmd, cancel := WithCancel(context.Background(), "sleep", "inf")
	require.NotNil(t, cancel, "No cancel function")
	require.NoError(t, cmd.Start(), "Failed to start command")
	cancel()
	_, err := cmd.CombinedOutput(true)
	assert.ErrorContains(t, err, "context canceled")
}

func Test_CombinedOutput(t *testing.T) {
	t.Run("TEST SUCCESS: combined output", func(t *testing.T) {
		cmd := CommandContext(context.Background(), "echo", "foo")
		out, err := cmd.CombinedOutput(true)
		require.NoError(t, err)
		assert.Equal(t, "foo\n", string(out))
	})

	t.Run("TEST FAILURE: context deadline", func(t *testing.T) {
		cmd := WithTimeout(timeout, "sleep", "inf")
		time.Sleep(timeout)
		_, err := cmd.CombinedOutput(true)
		require.Error(t, err)
		assert.ErrorContains(t, err, "context deadline exceeded")
	})
}

func Test_Which(t *testing.T) {
	t.Run("TEST SUCCESS: command exists", func(t *testing.T) {
		binpath, err := Which("sh")
		require.NoError(t, err, "Failed to find binary: %v", err)
		locations := map[string]struct{}{
			"/usr/bin/sh": {},
			"/bin/sh":     {},
		}
		assert.Contains(t, locations, binpath)
	})
	t.Run("TEST FAILURE: command not found", func(t *testing.T) {
		_, err := Which("testxxx")
		require.Error(t, err)
		assert.ErrorContains(t, err, "not found")
	})
}
