package cpu

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/vietanhduong/wbpf/pkg/logging"
	"github.com/vietanhduong/wbpf/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogComponent, "cpu")

const (
	cpuOnline   = "/sys/devices/system/cpu/online"
	possibleCpu = "/sys/devices/system/cpu/possible"
)

// OnlineCPUs returns a slice with the online CPUs, for example `[0, 2, 3]`
func OnlineCPUs() ([]uint, error) {
	buf, err := os.ReadFile(cpuOnline)
	if err != nil {
		return nil, fmt.Errorf("os read file %s: %w", cpuOnline, err)
	}
	return readCpuRange(string(buf))
}

// PossibleCPUs returns a slice with the possible CPUs, for example `[0, 2, 3]`
func PossibleCPUs() ([]uint, error) {
	buf, err := os.ReadFile(possibleCpu)
	if err != nil {
		return nil, fmt.Errorf("os read file %s: %w", possibleCpu, err)
	}
	return readCpuRange(string(buf))
}

// loosely based on https://github.com/iovisor/bcc/blob/v0.3.0/src/python/bcc/utils.py#L15
func readCpuRange(str string) ([]uint, error) {
	var cpus []uint
	for _, s := range strings.Split(strings.TrimSpace(str), ",") {
		if idx := strings.Index(s, "-"); idx == -1 {
			n, err := strconv.ParseUint(s, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("strconv parse uint (%s): %w", s, err)
			}
			cpus = append(cpus, uint(n))
			continue
		} else {
			first, err := strconv.ParseUint(s[:idx], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("strconv parse uint (%s): %w", s[:idx], err)
			}
			last, err := strconv.ParseUint(s[idx+1:], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("strconv parse uint (%s): %w", s[idx+1:], err)
			}
			for n := first; n <= last; n++ {
				cpus = append(cpus, uint(n))
			}
		}
	}
	return cpus, nil
}
