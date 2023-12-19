package wbpf

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var ErrProgNotFound = fmt.Errorf("prog not found")

type Module struct {
	collection *ebpf.Collection

	kprobes  map[string]link.Link
	ringbufs map[string]*RingBuf
	perfbufs map[string]*PerfBuf
}

func NewModule(opts ...ModuleOption) (*Module, error) {
	var modOpts moduleOptions
	for _, opt := range opts {
		opt(&modOpts)
	}

	if (modOpts.file == "" && len(modOpts.content) == 0) ||
		(modOpts.file != "" && len(modOpts.content) != 0) {
		return nil, fmt.Errorf("only one of file or content must be specified")
	}
	mod, err := newModule(&modOpts)
	if err != nil {
		return nil, err
	}
	runtime.SetFinalizer(mod, func(m *Module) { m.Close() })
	return mod, nil
}

func (m *Module) GetTable(name string) (*Table, error) {
	tbl, ok := m.collection.Maps[name]
	if !ok || tbl == nil {
		return nil, ErrTableNotFound
	}
	info, err := tbl.Info()
	if err != nil {
		return nil, fmt.Errorf("map info: %w", err)
	}
	return &Table{Map: tbl, info: info, mod: m}, nil
}

func (m *Module) AttackKprobe(sysname, prog string) error {
	if _, ok := m.kprobes[sysname]; ok {
		return nil
	}

	p, ok := m.collection.Programs[prog]
	if !ok || p == nil {
		return ErrProgNotFound
	}
	kprobe, err := link.Kprobe(sysname, p, nil)
	if err != nil {
		return fmt.Errorf("link kprobe (%s): %w", sysname, err)
	}
	m.kprobes[sysname] = kprobe
	return nil
}

func (m *Module) DetachKprobe(sysname string) {
	if kprobe := m.kprobes[sysname]; kprobe != nil {
		kprobe.Close()
	}
	delete(m.kprobes, sysname)

	sysname = FixSyscallName(sysname)
	if kprobe := m.kprobes[sysname]; kprobe != nil {
		kprobe.Close()
	}
	delete(m.kprobes, sysname)
}

func (m *Module) OpenPerfBuffer(name string, opts *PerfBufOptions) error {
	if _, ok := m.perfbufs[name]; ok {
		return nil
	}
	tbl, err := m.GetTable(name)
	if err != nil {
		return fmt.Errorf("get table: %w", err)
	}

	buf, err := NewPerfBuffer(tbl, opts)
	if err != nil {
		return fmt.Errorf("new perf buffer: %w", err)
	}
	m.perfbufs[name] = buf
	return nil
}

func (m *Module) ClosePerfBuffer(name string) {
	if buf := m.perfbufs[name]; buf != nil {
		buf.Close()
	}
	delete(m.perfbufs, name)
}

func (m *Module) PollPerfBuffer(name string, timeout time.Duration) int {
	if buf := m.perfbufs[name]; buf != nil {
		count, _ := buf.Poll(timeout)
		return count
	}
	return -1
}

func (m *Module) OpenRingBuffer(name string, opts *RingBufOptions) error {
	if _, ok := m.ringbufs[name]; ok {
		return nil
	}

	tbl, err := m.GetTable(name)
	if err != nil {
		return fmt.Errorf("get table: %w", err)
	}

	buf, err := NewRingBuf(tbl, opts)
	if err != nil {
		return fmt.Errorf("new ringbuf: %w", err)
	}

	m.ringbufs[name] = buf
	return nil
}

func (m *Module) CloseRingBuffer(name string) {
	if buf := m.ringbufs[name]; buf != nil {
		buf.Close()
	}
	delete(m.ringbufs, name)
}

func (m *Module) PollRingBuffer(name string, timeout time.Duration) int {
	if buf, ok := m.ringbufs[name]; ok {
		count, _ := buf.Poll(timeout)
		return count
	}
	return -1
}

func (m *Module) Close() {
	if m == nil {
		return
	}
	// Close collection after all probes have been closed
	if m.collection != nil {
		defer m.collection.Close()
	}
	// Detach Kprobes
	for name := range m.kprobes {
		m.DetachKprobe(name)
	}
	// Close Ring Buffers
	for name := range m.ringbufs {
		m.CloseRingBuffer(name)
	}
	// Close Perf Buffers
	for name := range m.perfbufs {
		m.ClosePerfBuffer(name)
	}
}

func newModule(opts *moduleOptions) (*Module, error) {
	if opts.file != "" {
		buf, err := os.ReadFile(opts.file)
		if err != nil {
			return nil, fmt.Errorf("os read file: %w", err)
		}
		opts.content = buf
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(opts.content))
	if err != nil {
		return nil, fmt.Errorf("ebpf load collection spec: %w", err)
	}

	mod := &Module{
		kprobes:  make(map[string]link.Link),
		ringbufs: make(map[string]*RingBuf),
		perfbufs: make(map[string]*PerfBuf),
	}
	if mod.collection, err = ebpf.NewCollection(spec); err != nil {
		return nil, fmt.Errorf("ebpf new collection: %w", err)
	}
	return mod, nil
}
