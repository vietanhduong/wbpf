package proc

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/vietanhduong/wbpf/pkg/logging/logfields"
	"golang.org/x/sys/unix"
)

type Stat struct {
	pid            int
	procfs         string
	rootSymlink    string
	mountNsSymlink string
	commPath       string
	// file descriptor of /proc/<pid>/root open with O_PATH used to get into root
	// of process after it exits; unlike a dereferenced root symlink, *at calls
	// to this use the process's mount namespace
	rootFd int
	// store also root path and mount namespace pair to detect its change
	root    string
	mountNs string

	inode uint64
	info  *PidInfo
}

func ProcStat(pid int) (*Stat, error) {
	stat := &Stat{
		procfs:         HostProcPath(fmt.Sprintf("%d/exe", pid)),
		rootSymlink:    HostProcPath(fmt.Sprintf("%d/root", pid)),
		mountNsSymlink: HostProcPath(fmt.Sprintf("%d/ns/mnt", pid)),
		commPath:       HostProcPath(fmt.Sprintf("%d/comm", pid)),
		rootFd:         -1,
		pid:            pid,
	}
	var err error
	if stat.inode, err = getinode(stat.procfs); err != nil {
		return nil, fmt.Errorf("get inode: %w", err)
	}
	stat.RefreshRoot()
	return stat, nil
}

func (s *Stat) RefreshRoot() bool {
	// Try to get current root and current mount namespace for the process
	// If an error is raise, that means the process might not exists anymore;
	// keep the old fd
	realRoot, err := os.Readlink(s.rootSymlink)
	if err != nil {
		return false
	}
	realNsMnt, err := os.Readlink(s.mountNsSymlink)
	if err != nil {
		return false
	}
	// Check if the root FD is up-to-date
	if s.rootFd != -1 && s.root == realRoot && s.mountNs == realNsMnt {
		return false
	}
	s.root = realRoot
	s.mountNs = realNsMnt
	oldFd := s.rootFd
	s.rootFd, err = unix.Open(s.rootSymlink, unix.O_PATH, 0)
	if err != nil {
		log.WithFields(logrus.Fields{
			logfields.File: s.rootSymlink,
			logfields.PID:  s.pid,
		}).Tracef("Failed to open: %v", err)
	}
	if s.rootFd == oldFd { // should never happen
		return false
	}

	if oldFd > 0 {
		syscall.Close(oldFd)
	}

	if err = s.buildPidInfo(); err != nil {
		log.WithField(logfields.PID, s.pid).Tracef("Failed to build PID Info: %v", err)
	}
	return true
}

func (s *Stat) GetRootFD() int { return s.rootFd }

func (s *Stat) IsStale() bool {
	inode, _ := getinode(s.procfs)
	return inode != s.inode && s.RefreshRoot()
}

func (s *Stat) buildPidInfo() error {
	exePath, err := os.Readlink(s.procfs)
	if err != nil {
		return fmt.Errorf("read link %s: %w", s.procfs, err)
	}

	comm, err := os.ReadFile(s.commPath)
	if err != nil {
		return fmt.Errorf("read file %s: %w", s.commPath, err)
	}
	if comm[len(comm)-1] == '\n' {
		comm = comm[:len(comm)-1]
	}
	starttime, err := getProcStartTime(s.pid)
	if err != nil {
		return fmt.Errorf("get proc %d start time: %w", s.pid, err)
	}
	s.info = &PidInfo{
		Pid:       s.pid,
		Exe:       filepath.Base(exePath),
		Comm:      string(comm),
		StartTime: starttime,
	}
	return nil
}

func (s *Stat) PidInfo() *PidInfo { return s.info }

func (s *Stat) Reset() { s.inode, _ = getinode(s.procfs) }

func getinode(procfs string) (uint64, error) {
	var stat unix.Stat_t
	if err := unix.Stat(procfs, &stat); err != nil {
		return 0, fmt.Errorf("unix stat %s: %w", procfs, err)
	}
	return stat.Ino, nil
}
