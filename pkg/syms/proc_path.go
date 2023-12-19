package syms

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/vietanhduong/wbpf/pkg/proc"
	"golang.org/x/sys/unix"
)

type procPath struct {
	path         string
	procRootPath string
	fd           int
}

func newProcPath(path string, pid, rootfd int, inMem bool) *procPath {
	this := &procPath{}
	if inMem {
		this.path = path
		this.procRootPath = path
		return this
	}

	this.procRootPath = proc.HostProcPath(fmt.Sprintf("%d/root", pid), path)
	trimmedPath := strings.TrimPrefix(filepath.Join(path), "/")
	var err error
	this.fd, err = unix.Openat(rootfd, trimmedPath, unix.O_RDONLY, 0)
	if err == nil {
		this.path = proc.HostProcPath(fmt.Sprintf("self/fd/%d", this.fd))
		runtime.SetFinalizer(this, func(obj *procPath) { obj.Close() })
	} else {
		this.path = this.procRootPath
	}
	return this
}

func (p *procPath) GetPath() string {
	if p.path == p.procRootPath || unix.Access(p.procRootPath, unix.F_OK) != nil {
		return p.path
	}
	return p.GetRootPath()
}

func (p *procPath) GetRootPath() string { return p.procRootPath }

func (p *procPath) Close() { syscall.Close(p.fd) }
