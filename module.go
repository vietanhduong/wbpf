package wbpf

import (
	"bytes"
	"fmt"
	"os"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var ErrProgNotFound = fmt.Errorf("prog not found")

type Module struct {
	collection *ebpf.Collection

	kprobes map[string]link.Link
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
	sysname = GetSyscallName(sysname)
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
	sysname = GetSyscallName(sysname)
	if kprobe, ok := m.kprobes[sysname]; ok {
		kprobe.Close()
		delete(m.kprobes, sysname)
	}
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
	for name, l := range m.kprobes {
		l.Close()
		delete(m.kprobes, name)
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
		kprobes: make(map[string]link.Link),
	}
	if mod.collection, err = ebpf.NewCollection(spec); err != nil {
		return nil, fmt.Errorf("ebpf new collection: %w", err)
	}
	return mod, nil
}
