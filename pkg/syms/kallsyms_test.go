package syms

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseKallsyms(t *testing.T) {
	symbols, err := parseKallsyms("./testdata/kallsyms")
	require.NoError(t, err, "Failed to parse kallsyms")

	var expected []Symbol
	readJson(t, "./testdata/kallsyms.expected.json", &expected)
	diff := cmp.Diff(expected, symbols)
	assert.Empty(t, diff, "Diff (-want,+got):\n%s", diff)
}

func readJson(t *testing.T, path string, out any) {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err, "Failed to read path %s", path)
	err = json.Unmarshal(b, out)
	require.NoError(t, err, "Failed to unmarshal json")
}
