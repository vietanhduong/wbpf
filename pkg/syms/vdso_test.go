package syms

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_buildVDSOResolver(t *testing.T) {
	resolver, err := buildVDSOResolver()
	require.NoError(t, err)
	assert.True(t, resolver.Size() > 0)
}
