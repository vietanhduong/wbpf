package wbpf

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var ErrProgNotFound = fmt.Errorf("prog not found")

type Module struct {
	collection *ebpf.Collection

	kprobes     map[string]link.Link
	ringbufs    map[string]*RingBuf
	perfbufs    map[string]*PerfBuf
	tracepoints map[string]link.Link
	rawtps      map[string]link.Link
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

func (m *Module) AttachKprobe(sysname, prog string) error {
	return m.attachKprobe(sysname, prog, false)
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

func (m *Module) AttachKretprobe(sysname, prog string) error {
	return m.attachKprobe(sysname, prog, true)
}

// AttachTracepoint attaches a tracepoint to the input prog.
// The input name must be in the format 'group:name'
func (m *Module) AttachTracepoint(name, prog string) error {
	if _, ok := m.tracepoints[name]; ok {
		return nil
	}
	parts := strings.SplitN(name, ":", 2)
	if len(parts) < 2 {
		return fmt.Errorf("invalid tracepoint name, expected %q but got %q", "<group>:<name>", name)
	}

	p, ok := m.collection.Programs[prog]
	if !ok || p == nil {
		return ErrProgNotFound
	}

	tp, err := link.Tracepoint(parts[0], parts[1], p, nil)
	if err != nil {
		return fmt.Errorf("link tracepoint: %w", err)
	}
	m.tracepoints[name] = tp
	return nil
}

func (m *Module) DetachTracepoint(name string) {
	if tp := m.tracepoints[name]; tp != nil {
		tp.Close()
	}
	delete(m.tracepoints, name)
}

// AttachRawTracepoint attaches a raw tracepoint to the input prog.
// The input name is in the format 'name', there is no group.
func (m *Module) AttachRawTracepoint(name, prog string) error {
	if _, ok := m.rawtps[name]; ok {
		return nil
	}

	p, ok := m.collection.Programs[prog]
	if !ok || p == nil {
		return ErrProgNotFound
	}

	rawtp, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: name, Program: p})
	if err != nil {
		return fmt.Errorf("link attach raw tracepoint %s: %w", name, err)
	}
	m.rawtps[name] = rawtp
	return nil
}

func (m *Module) DetachRawTracepoint(name string) {
	if rawtp := m.rawtps[name]; rawtp != nil {
		rawtp.Close()
	}
	delete(m.rawtps, name)
}

func (m *Module) attachKprobe(sysname, prog string, ret bool) error {
	if _, ok := m.kprobes[sysname]; ok {
		return nil
	}

	p, ok := m.collection.Programs[prog]
	if !ok || p == nil {
		return ErrProgNotFound
	}

	var fn func(symbol string, prog *ebpf.Program, opts *link.KprobeOptions) (link.Link, error)
	var fnname string
	if ret {
		fn = link.Kretprobe
		fnname = "kretprobe"
	} else {
		fn = link.Kprobe
		fnname = "kprobe"
	}

	kprobe, err := fn(sysname, p, nil)
	if err != nil {
		return fmt.Errorf("link %s (%s): %w", fnname, sysname, err)
	}
	m.kprobes[sysname] = kprobe
	return nil
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
	// Detach Raw Tracepoints
	for name := range m.rawtps {
		m.DetachRawTracepoint(name)
	}
	// Detach Tracepoints
	for name := range m.tracepoints {
		m.DetachTracepoint(name)
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
		kprobes:     make(map[string]link.Link),
		ringbufs:    make(map[string]*RingBuf),
		perfbufs:    make(map[string]*PerfBuf),
		tracepoints: make(map[string]link.Link),
		rawtps:      make(map[string]link.Link),
	}
	if mod.collection, err = ebpf.NewCollection(spec); err != nil {
		return nil, fmt.Errorf("ebpf new collection: %w", err)
	}
	return mod, nil
}
