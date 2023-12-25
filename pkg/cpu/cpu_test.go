package cpu

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_readCpuRange(t *testing.T) {
	testcases := []struct {
		input  string
		expect []uint
	}{
		{
			input:  "0-5\n",
			expect: []uint{0, 1, 2, 3, 4, 5},
		},
		{
			input:  "0-2,7,9-11",
			expect: []uint{0, 1, 2, 7, 9, 10, 11},
		},
	}
	for _, tt := range testcases {
		t.Run(fmt.Sprintf("cpu: %s", tt.input), func(t *testing.T) {
			cpus, err := readCpuRange(tt.input)
			require.NoError(t, err, "Failed to read cpu range: %v", err)
			assert.Equal(t, tt.expect, cpus)
		})
	}
}
