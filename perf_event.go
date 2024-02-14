package wbpf

import (
	"fmt"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/hashicorp/go-multierror"
	"github.com/vietanhduong/wbpf/pkg/cpu"
	"golang.org/x/sys/unix"
)

// PerfEventOptions follow unix.PerfEventAttr
type PerfEventOptions struct {
	Type       uint32
	Config     uint64
	SampleRate uint64
}

type perfEventEntry struct {
	perfFd  int
	rawlink *link.RawLink
}

type PerfEvent struct {
	prog *ebpf.Program
	cpus map[int]*perfEventEntry
}

func NewPerfEvent(prog *ebpf.Program, opts PerfEventOptions) (*PerfEvent, error) {
	cpus, err := cpu.OnlineCPUs()
	if err != nil {
		return nil, fmt.Errorf("get cpu online: %w", err)
	}

	this := &PerfEvent{
		prog: prog,
		cpus: make(map[int]*perfEventEntry, len(cpus)),
	}

	for _, cpu := range cpus {
		this.cpus[int(cpu)], err = this.attachPerfEventOnCpu(int(cpu), opts)
		if err != nil {
			this.Close()
			return nil, fmt.Errorf("attach perf event on cpu %d: %w", cpu, err)
		}
	}
	return this, nil
}

func (pe *PerfEvent) Close() error {
	if pe == nil {
		return nil
	}
	var err error
	for _, entry := range pe.cpus {
		if err2 := entry.Close(); err != nil {
			err = multierror.Append(err, err2)
		}
	}
	clear(pe.cpus)
	return err
}

func (p *perfEventEntry) Close() error {
	if p == nil {
		return nil
	}
	_ = syscall.Close(p.perfFd)
	if p.rawlink != nil {
		return p.rawlink.Close()
	}
	return nil
}

func (pe *PerfEvent) attachPerfEventOnCpu(cpu int, opts PerfEventOptions) (*perfEventEntry, error) {
	perfFd, err := openPerfEventCpu(cpu, opts)
	if err != nil {
		return nil, err
	}
	entry := &perfEventEntry{perfFd: perfFd}
	if entry.rawlink, err = pe.attachPerfEventLink(perfFd); err == nil {
		return entry, nil
	}
	if err = pe.attachPerfEventIoctl(perfFd); err != nil {
		entry.Close()
		return nil, err
	}
	return entry, nil
}

func (pe *PerfEvent) attachPerfEventLink(perfFd int) (*link.RawLink, error) {
	opts := link.RawLinkOptions{
		Target:  perfFd,
		Program: pe.prog,
		Attach:  ebpf.AttachPerfEvent,
	}
	link, err := link.AttachRawLink(opts)
	if err != nil {
		return nil, fmt.Errorf("attach raw link: %w", err)
	}
	return link, nil
}

func (pe *PerfEvent) attachPerfEventIoctl(perfFd int) error {
	err := unix.IoctlSetInt(perfFd, unix.PERF_EVENT_IOC_SET_BPF, pe.prog.FD())
	if err != nil {
		return fmt.Errorf("setting perf event bpf program: %w", err)
	}
	if err = unix.IoctlSetInt(perfFd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		return fmt.Errorf("enable perf event: %w", err)
	}
	return nil
}

func openPerfEventCpu(cpu int, opts PerfEventOptions) (int, error) {
	attr := unix.PerfEventAttr{
		Type:   opts.Type,
		Config: opts.Config,
		Bits:   unix.PerfBitFreq,
		Sample: opts.SampleRate,
	}
	fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return -1, fmt.Errorf("unix perf event open: %w", err)
	}
	return fd, nil
}
