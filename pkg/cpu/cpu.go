package cpu

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/vietanhduong/wbpf/pkg/logging"
	"github.com/vietanhduong/wbpf/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogComponent, "cpu")

var (
	probeCPUOnce sync.Once
	// default fallback
	nameBPFCPU = "v1"
)

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

// GetBPFCPU returns the BPF CPU for this host.
func GetBPFCPU() string {
	probeCPUOnce.Do(func() {
		if haveV3ISA() == nil {
			if haveProgramHelper(ebpf.SchedCLS, asm.FnRedirectNeigh) == nil {
				nameBPFCPU = "v3"
				return
			}
		}
		// We want to enable v2 on all kernels that support it, that is,
		// kernels 4.14+.
		if haveV2ISA() == nil {
			nameBPFCPU = "v2"
		}
	})
	return nameBPFCPU
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

func haveV3ISA() error {
	err := features.HaveV3ISA()
	if errors.Is(err, ebpf.ErrNotSupported) {
		return err
	}
	if err != nil {
		log.WithError(err).Fatal("failed to probe V3 ISA")
	}
	return nil
}

func haveV2ISA() error {
	err := features.HaveV2ISA()
	if errors.Is(err, ebpf.ErrNotSupported) {
		return err
	}
	if err != nil {
		log.WithError(err).Fatal("failed to probe V2 ISA")
	}
	return nil
}

func haveProgramHelper(pt ebpf.ProgramType, helper asm.BuiltinFunc) error {
	err := features.HaveProgramHelper(pt, helper)
	if errors.Is(err, ebpf.ErrNotSupported) {
		return err
	}
	if err != nil {
		log.WithError(err).WithField("programtype", pt).WithField("helper", helper).Fatal("failed to probe helper")
	}
	return nil
}
