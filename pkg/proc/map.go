package proc

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func ParseProcMaps(pid int) ([]*Map, error) {
	mapfile := HostProcPath(fmt.Sprintf("%d", pid), "maps")
	f, err := os.Open(mapfile)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", mapfile, err)
	}
	defer f.Close()

	ret, err := parseProcMap(f, pid)
	if err != nil {
		log.Warnf("Failed to parse proc map %s: %v", mapfile, err)
	}

	var perfmap string
	if perfmap = FindPerfMapPath(pid); perfmap != "" && unix.Access(perfmap, unix.R_OK) == nil {
		ret = append(ret, &Map{Pathname: perfmap})
	}

	tmpPerf := fmt.Sprintf("/tmp/perf-%d.map", pid)
	if perfmap == tmpPerf {
		return ret, nil
	}

	// Normally, this will never happen. Because the FindPerfMap should
	// always return a read file at /tmp/perf-<pid>.map at the host root
	// dir if posible
	if unix.Access(tmpPerf, unix.R_OK) == nil {
		ret = append(ret, &Map{Pathname: tmpPerf})
	}
	return ret, nil
}

func FindPerfMapPath(pid int) string {
	rootpath := HostProcPath(fmt.Sprintf("%d/root", pid))
	target, err := os.Readlink(rootpath)
	if err != nil {
		return ""
	}
	if nstigd := FindPerfMapNStgid(pid); nstigd != -1 {
		return filepath.Join(target, fmt.Sprintf("tmp/perf-%d.map", nstigd))
	}
	return ""
}

func FindPerfMapNStgid(pid int) int {
	nstgid := -1
	statuspath := HostProcPath(fmt.Sprintf("%d/status", pid))
	f, err := os.Open(statuspath)
	if err != nil {
		return nstgid
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// check Tgid line first in case CONFIG_PID_NS is off
		if strings.HasPrefix(line, "Tgid:") {
			nstgid, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Tgid:")))
		}
		// PID namespaces can be nested -- last number is innermost PID
		if strings.HasPrefix(line, "NStgid:") {
			nstgid, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "NStgid:")))
		}
	}
	if err = scanner.Err(); err != nil {
		return -1
	}
	return nstgid
}

func parseProcMap(f *os.File, pid int) ([]*Map, error) {
	var ret []*Map
	for {
		var m Map
		var perm, buf string
		n, _ := fmt.Fscanf(f, "%x-%x %4s %x %x:%x %d %s\n",
			&m.StartAddr,
			&m.EndAddr,
			&perm,
			&m.FileOffset,
			&m.DevMajor,
			&m.DevMinor,
			&m.Inode,
			&buf)
		if n > 8 || n < 7 {
			break
		}

		if len(perm) != 4 || perm[2] != 'x' { // executable only
			continue
		}
		m.Pathname = strings.TrimSpace(buf)

		if isFileBacked(m.Pathname) {
			continue
		}

		var pathname string
		if strings.Contains(m.Pathname, "/memfd:") {
			if pathname = findMemFdPath(pid, m.Inode); pathname != "" {
				m.InMem = true
			}
		}
		// TODO(vietanhduong): handle zip and apk

		if pathname != "" {
			m.Pathname = pathname
		}
		ret = append(ret, &m)
	}
	return ret, nil
}

func isFileBacked(mapname string) bool {
	return mapname != "" && (strings.HasPrefix(mapname, "//anon") ||
		strings.HasPrefix(mapname, "/dev/zero") ||
		strings.HasPrefix(mapname, "/anon_hugepage") ||
		strings.HasPrefix(mapname, "[stack") ||
		strings.HasPrefix(mapname, "/SYSV") ||
		strings.HasPrefix(mapname, "[heap]") ||
		strings.HasPrefix(mapname, "[vsyscall]"))
}

func findMemFdPath(pid int, inode uint64) string {
	fdpath := HostProcPath(fmt.Sprintf("%d/fd", pid))
	entries, err := os.ReadDir(fdpath)
	if err != nil {
		log.Warnf("Failed to list directory entry at %s, error: %v", fdpath, err)
		return ""
	}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		if info, _ := ent.Info(); info != nil {
			if stats, ok := info.Sys().(*syscall.Stat_t); ok && stats.Ino == inode {
				return filepath.Join(fdpath, ent.Name())
			}
		}
	}
	return ""
}
