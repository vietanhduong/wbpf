package proc

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tklauser/go-sysconf"
)

func getProcStartTime(pid int) (time.Time, error) {
	var ret time.Time
	clktck, err := sysconf.Sysconf(sysconf.SC_CLK_TCK)
	if err != nil {
		return ret, fmt.Errorf("get sysconf SC_CLK_TCK: %w", err)
	}
	statfile := HostProcPath(fmt.Sprintf("%d/stat", pid))
	b, err := os.ReadFile(statfile)
	if err != nil {
		return ret, fmt.Errorf("read file %s: %w", statfile, err)
	}
	parts := strings.Fields(string(b))
	if len(parts) != 52 {
		return ret, fmt.Errorf("stat file %s has invalid format, expected 52 columns but got %d", statfile, len(parts))
	}
	// Follow convention https://github.com/torvalds/linux/blob/master/fs/proc/array.c#L467
	// or man 5 proc => /proc/[PID]/stat
	starttime, _ := strconv.ParseFloat(parts[21], 64)
	if starttime == 0 {
		return ret, fmt.Errorf("stat file %s has invalid starttime column (%s)", statfile, parts[21])
	}

	starttime /= float64(clktck)

	uptime, err := getUptime()
	if err != nil {
		return ret, fmt.Errorf("get uptime: %w", err)
	}

	diff := time.Duration(uptime-starttime) * time.Second
	return time.Now().Add(-diff), nil
}

func getUptime() (float64, error) {
	uptimefile := HostProcPath("uptime")
	data, err := os.ReadFile(uptimefile)
	if err != nil {
		return -1, fmt.Errorf("read file %s: %w", uptimefile, err)
	}
	parts := strings.Fields(string(data))
	if len(parts) != 2 {
		return -1, fmt.Errorf("invalid uptime file expected 2 columns but got %d", len(parts))
	}
	uptime, _ := strconv.ParseFloat(parts[0], 64)
	if uptime == 0 {
		return -1, fmt.Errorf("invalid uptime value (%s)", parts[0])
	}
	return uptime, nil
}
