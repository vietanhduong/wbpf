package proc

import (
	"fmt"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

type Map struct {
	Pathname   string
	StartAddr  uint64
	EndAddr    uint64
	FileOffset uint
	DevMajor   uint32
	DevMinor   uint32
	Inode      uint64
	InMem      bool
}

func (m *Map) String() string {
	if m == nil {
		return ""
	}

	return fmt.Sprintf("%s 0x%016x-0x%016x 0x%016x %x:%x %d %t",
		m.Pathname,
		m.StartAddr,
		m.EndAddr,
		m.FileOffset,
		m.DevMajor,
		m.DevMinor,
		m.Inode,
		m.InMem)
}

type File struct {
	Dev   uint64
	Inode uint64
	Path  string
}

func (m *Map) File() File {
	return File{
		Inode: m.Inode,
		Path:  m.Pathname,
		Dev:   unix.Mkdev(m.DevMajor, m.DevMinor),
	}
}

type Pid int

func (p Pid) String() string { return strconv.FormatInt(int64(p), 10) }

type PidInfo struct {
	Pid       int
	Exe       string
	Comm      string
	StartTime time.Time
}

func (p *PidInfo) DeepCopy() *PidInfo {
	if p == nil {
		return nil
	}
	cp := *p
	return &cp
}

func (p *PidInfo) String() string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("pid=%d exe=%s comm=%s starttime=%s", p.Pid, p.Exe, p.Comm, p.StartTime.Format(time.RFC3339))
}
