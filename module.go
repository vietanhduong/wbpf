package wbpf

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	lru "github.com/hashicorp/golang-lru/v2"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/sirupsen/logrus"
	"github.com/vietanhduong/wbpf/pkg/logging"
	"github.com/vietanhduong/wbpf/pkg/logging/logfields"
	"github.com/vietanhduong/wbpf/pkg/syms"
	"github.com/vietanhduong/wbpf/pkg/utils"
)

var log = logging.DefaultLogger.WithFields(logrus.Fields{logfields.LogSubsys: "module"})

var ErrProgNotFound = fmt.Errorf("prog not found")

type Module struct {
	collection *ebpf.Collection

	kprobes     cmap.ConcurrentMap[string, link.Link]
	uprobes     cmap.ConcurrentMap[string, *uprobe]
	ringbufs    cmap.ConcurrentMap[string, *RingBuf]
	perfbufs    cmap.ConcurrentMap[string, *PerfBuf]
	tracepoints cmap.ConcurrentMap[string, link.Link]
	rawtps      cmap.ConcurrentMap[string, link.Link]
	perfEvents  cmap.ConcurrentMap[string, *PerfEvent]
	xdps        cmap.ConcurrentMap[string, link.Link]

	symcaches *lru.Cache[int, syms.Resolver]
}

// NewModule creates a new eBPF module from the given file or content.
// Only one of file or content must be specified.
func NewModule(opts ...ModuleOption) (*Module, error) {
	modOpts := defaultModuleOpts()
	for _, opt := range opts {
		opt(modOpts)
	}

	if (modOpts.file == "" && len(modOpts.content) == 0) ||
		(modOpts.file != "" && len(modOpts.content) != 0) {
		return nil, fmt.Errorf("only one of file or content must be specified")
	}
	mod, err := newModule(modOpts)
	if err != nil {
		return nil, err
	}
	runtime.SetFinalizer(mod, func(m *Module) { m.Close() })
	return mod, nil
}

// GetTable returns the table with the given name.
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

// Kprobe attaches the given eBPF program to a perf event that fires when the
// given kernel symbol starts executing. See /proc/kallsyms for available
// symbols. For example, printk():
//
//	err := mod.AttachKprobe("printk", prog)
//
// This function will assume that the syscall is correct. Therefore, the input
// syscall must be fixed before pass through this.
func (m *Module) AttachKprobe(sysname, prog string) error {
	return m.attachKprobe(sysname, prog, false)
}

func (m *Module) DetachKprobe(sysname string) {
	detach := func(name string) {
		if kprobe, _ := m.kprobes.Get(name); !utils.IsNil(kprobe) {
			kprobe.Close()
		}
		m.kprobes.Remove(name)
	}
	detach(sysname)
	detach(FixSyscallName(sysname))
}

// AttachKretprobe attaches the given eBPF program to a perf event that fires
// right before the given kernel symbol exits, with the function stack left
// intact.
// See /proc/kallsyms for available symbols. For example, printk():
//
//	kp, err := Kretprobe("printk", prog, nil)
//
// This function will assume that the syscall is correct. Therefore, the input
// syscall must be fixed before pass through this.
func (m *Module) AttachKretprobe(sysname, prog string) error {
	return m.attachKprobe(sysname, prog, true)
}

// AttachTracepoint attaches a tracepoint to the input prog.
// The input name must be in the format 'group:name'
func (m *Module) AttachTracepoint(name, prog string) error {
	if m.tracepoints.Has(name) {
		return nil
	}
	parts := strings.SplitN(name, ":", 2)
	if len(parts) < 2 {
		return fmt.Errorf("invalid tracepoint name, expected %q but got %q", "<group>:<name>", name)
	}

	p, err := m.GetProg(prog)
	if err != nil {
		return err
	}

	tp, err := link.Tracepoint(parts[0], parts[1], p, nil)
	if err != nil {
		return fmt.Errorf("link tracepoint: %w", err)
	}
	m.tracepoints.Set(name, tp)
	return nil
}

// DetachTracepoint detaches the tracepoint with the given name.
// The input name must be in the format 'group:name'
func (m *Module) DetachTracepoint(name string) {
	if tp, _ := m.tracepoints.Get(name); !utils.IsNil(tp) {
		tp.Close()
	}
	m.tracepoints.Remove(name)
}

// AttachRawTracepoint attaches a raw tracepoint to the input prog.
// The input name is in the format 'name', there is no group.
func (m *Module) AttachRawTracepoint(name, prog string) error {
	if m.rawtps.Has(name) {
		return nil
	}

	p, err := m.GetProg(prog)
	if err != nil {
		return err
	}

	rawtp, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: name, Program: p})
	if err != nil {
		return fmt.Errorf("link attach raw tracepoint %s: %w", name, err)
	}
	m.rawtps.Set(name, rawtp)
	return nil
}

// DetachRawTracepoint detaches the raw tracepoint with the given name.
// The input name is in the format 'name', there is no group.
func (m *Module) DetachRawTracepoint(name string) {
	if rawtp, _ := m.rawtps.Get(name); !utils.IsNil(rawtp) {
		rawtp.Close()
	}
	m.rawtps.Remove(name)
}

// AttachPerfEvent attaches the given eBPF program to a perf event that fires
// when the given event occurs. See /sys/bus/event_source/devices/ for available
// events.
func (m *Module) AttachPerfEvent(prog string, opts PerfEventOptions) error {
	if m.perfEvents.Has(prog) {
		return nil
	}
	p, err := m.GetProg(prog)
	if err != nil {
		return err
	}
	event, err := NewPerfEvent(p, opts)
	if err != nil {
		return fmt.Errorf("new perf event: %w", err)
	}
	m.perfEvents.Set(prog, event)
	return nil
}

func (m *Module) DetachPerfEvent(prog string) {
	if event, _ := m.perfEvents.Get(prog); event != nil {
		event.Close()
	}
	m.perfEvents.Remove(prog)
}

func (m *Module) attachKprobe(sysname, prog string, ret bool) error {
	if m.kprobes.Has(sysname) {
		return nil
	}

	p, err := m.GetProg(prog)
	if err != nil {
		return err
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
	m.kprobes.Set(sysname, kprobe)
	return nil
}

// AttachUprobe attaches the given eBPF program to a perf event that fires when the
// given symbol starts executing in the given Executable.
// For example, /bin/bash::main():
//
//	mod.AttachUprobe("/bin/bash", prog, &UprobeOptions{SymbolName: "main"})
//
// When using symbols which belongs to shared libraries,
// an offset must be provided via options:
//
//	mod.AttachUprobe("/bin/bash", prog, &UprobeOptions{SymbolName: "main", Offset: 0x123})
//
// Note: Setting the Offset field in the options supersedes the symbol's offset.
//
// You also able to attach multi-symbols by regex matching:
//
//	mod.AttachUprobe("/bin/bash", prog, &UprobeOptions{SymbolPattern: "ma*"})
//
// Note: Only SymbolPattern or SymbolName must be specified
//
// Losing the reference to the resulting Link (up) will close the Uprobe
// and prevent further execution of prog. The Link must be Closed during
// program shutdown to avoid leaking system resources.
//
// Functions provided by shared libraries can currently not be traced and
// will result in an ErrNotSupported.
func (m *Module) AttachUprobe(module, prog string, opts *UprobeOptions) error {
	return m.attachUprobe(module, prog, false, opts)
}

// AttachUretprobe attaches the given eBPF program to a perf event that fires right
// before the given symbol exits.
// For example, /bin/bash::main():
//
//	mod.AttachURetprobe("/bin/bash", prog, &UprobeOptions{SymbolName: "main"})
//
// When using symbols which belongs to shared libraries,
// an offset must be provided via options:
//
//	mod.AttachUprobe("/bin/bash", prog, &UprobeOptions{SymbolName: "main", Offset: 0x123})
//
// Note: Setting the Offset field in the options supersedes the symbol's offset.
//
// You also able to attach multi-symbols by regex matching:
//
//	mod.AttachUprobe("/bin/bash", prog, &UprobeOptions{SymbolPattern: "ma*"})
//
// Note: Only SymbolPattern or SymbolName must be specified
//
// Losing the reference to the resulting Link (up) will close the Uprobe
// and prevent further execution of prog. The Link must be Closed during
// program shutdown to avoid leaking system resources.
//
// Functions provided by shared libraries can currently not be traced and
// will result in an ErrNotSupported.
func (m *Module) AttachUretprobe(module, prog string, opts *UprobeOptions) error {
	return m.attachUprobe(module, prog, true, opts)
}

func (m *Module) attachUprobe(module, prog string, ret bool, opts *UprobeOptions) error {
	p, err := m.GetProg(prog)
	if err != nil {
		return err
	}

	probes, err := attachUprobe(module, p, ret, opts)
	if err != nil {
		return err
	}

	// We need to ensure that if a probe already be registered, and a new one come in,
	// the older must be closed before be override. The avoid a resource leak.
	for _, probe := range probes {
		if key := probe.keygen(); m.uprobes.Has(key) {
			log.Warnf("uprobe %s already registered, prepare to close it before override with new uprobe", key)
			old, _ := m.uprobes.Get(key)
			old.Close()
		} else {
			m.uprobes.Set(key, probe)
		}
	}
	return nil
}

// AttachXDP links an XDP BPF program to an XDP hook. The input ifname is the name of
// the network interface to which you want to attach the input program.
// The input flags must conform to the link.XDPAttachFlags enum.
func (m *Module) AttachXDP(ifname, prog string, flags uint64) error {
	p, err := m.GetProg(prog)
	if err != nil {
		return err
	}

	i, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("net interface by name: %w", err)
	}
	log.Debugf("found interface %s at index: %d", i.Name, i.Index)

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   p,
		Interface: i.Index,
		Flags:     link.XDPAttachFlags(flags),
	})
	if err != nil {
		return fmt.Errorf("link attach xdp: %w", err)
	}
	m.xdps.Set(ifname, l)
	return nil
}

func (m *Module) DetachXDP(ifname string) {
	if l, _ := m.xdps.Get(ifname); !utils.IsNil(l) {
		l.Close()
	}
	m.xdps.Remove(ifname)
}

// OpenPerfBuffer opens a perf buffer for the given table. The input opts is optional.
// If opts is nil, the default options will be used.
func (m *Module) OpenPerfBuffer(name string, opts *PerfBufOptions) error {
	if m.perfbufs.Has(name) {
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
	m.perfbufs.Set(name, buf)
	return nil
}

// ClosePerfBuffer closes the perf buffer with the given name.
func (m *Module) ClosePerfBuffer(name string) {
	if buf, _ := m.perfbufs.Get(name); buf != nil {
		buf.Close()
	}
	m.perfbufs.Remove(name)
}

// GetPerfBuffer returns the perf buffer with the given name.
// If the perf buffer is not found, nil will be returned.
func (m *Module) GetPerfBuffer(name string) *PerfBuf {
	buf, _ := m.perfbufs.Get(name)
	return buf
}

// PollPerfBuffer polls the perf buffer with the given name.
// If timeout is zero, the poll will return immediately.
// If timeout is negative, the poll will block until an event is available.
func (m *Module) PollPerfBuffer(name string, timeout time.Duration) int {
	if buf, _ := m.perfbufs.Get(name); buf != nil {
		count, _ := buf.Poll(timeout)
		return count
	}
	return -1
}

// OpenRingBuffer opens a ring buffer for the given table. The input opts is optional.
func (m *Module) OpenRingBuffer(name string, opts *RingBufOptions) error {
	if m.ringbufs.Has(name) {
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

	m.ringbufs.Set(name, buf)
	return nil
}

// CloseRingBuffer closes the ring buffer with the given name.
func (m *Module) CloseRingBuffer(name string) {
	if buf, _ := m.ringbufs.Get(name); buf != nil {
		buf.Close()
	}
	m.ringbufs.Remove(name)
}

// GetRingBuffer returns the ring buffer with the given name.
func (m *Module) GetRingBuffer(name string) *RingBuf {
	buf, _ := m.ringbufs.Get(name)
	return buf
}

// PollRingBuffer polls the ring buffer with the given name. If timeout is zero,
// the poll will return immediately. If timeout is negative, the poll will block
// until an event is available.
func (m *Module) PollRingBuffer(name string, timeout time.Duration) int {
	if buf, _ := m.ringbufs.Get(name); buf != nil {
		count, _ := buf.Poll(timeout)
		return count
	}
	return -1
}

func (m *Module) GetProg(name string) (*ebpf.Program, error) {
	if name == "" {
		return nil, fmt.Errorf("prog name is empty")
	}
	p, ok := m.collection.Programs[name]
	if !ok || p == nil {
		return nil, ErrProgNotFound
	}
	return p, nil
}

type ResolveSymbolOptions struct {
	ShowOffset bool
	ShowModule bool
}

// ResolveSymbol Translate a memory address into a function name for a pid, which is returned.
// When the show module option is set, the module name is also included. When the show offset
// is set, the instruction offset as a hexadecimal number is also included in the return string.
// A pid of lss than zero will access the kernel symbol cache.
//
// Example output when both show module and show offset are set:
//
//	"net/http.HandlerFunc.ServeHTTP+0x0000002f [.app]"
//
// Example output when both show module and show offset are unset:
//
//	"net/http.HandlerFunc.ServeHTTP"
func (m *Module) ResolveSymbol(pid int, addr uint64, opts ResolveSymbolOptions) string {
	cache := m.GetOrCreateSymbolCache(pid)
	sym := cache.Resolve(addr)
	if sym.Name == "" && sym.Module == "" {
		return fmt.Sprintf("0x%016x", addr)
	}

	var offset string
	var module string
	if sym.Name != "" && opts.ShowOffset {
		offset = fmt.Sprintf("+0x%08x", sym.Start)
	}
	name := sym.Name
	if name == "" {
		name = "<unknown>"
	}
	name += offset
	if sym.Module != "" && opts.ShowModule {
		module = fmt.Sprintf(" [%s]", path.Base(sym.Module))
	}

	return name + module
}

// ResolveKernelSymbol translate a kernel memory address into a kernel function name, which
// is returned. When the show module is set, the module name ("kernel") is also included.
// When the show offset is set, the instruction offset as a hexadecimal number is also
// included in the string
//
// Example outout when both show module and show offset are set:
//
//	"__x64_sys_epoll_pwait+0x00000077 [kernel]"
func (bpf *Module) ResolveKernelSymbol(addr uint64, opts ResolveSymbolOptions) string {
	return bpf.ResolveSymbol(-1, addr, opts)
}

func (m *Module) GetOrCreateSymbolCache(pid int) syms.Resolver {
	cache, ok := m.symcaches.Get(pid)
	if ok {
		return cache
	}
	cache, err := syms.NewResolver(pid, nil)
	if err != nil {
		log.WithField(logfields.PID, pid).Warnf("Failed to create symbol resolver: %v", err)
		cache = &syms.EmptyResolver{}
	}
	m.symcaches.Add(pid, cache)
	return cache
}

// Close closes the module and all of its resources.
// This function is expected to be call when the module is no longer needed to avoid
// resource leak.
func (m *Module) Close() {
	if m == nil {
		return
	}
	// Close collection after all probes have been closed
	if m.collection != nil {
		defer m.collection.Close()
	}
	// Detach Kprobes
	for _, name := range m.kprobes.Keys() {
		m.DetachKprobe(name)
	}
	// Close Ring Buffers
	for _, name := range m.ringbufs.Keys() {
		m.CloseRingBuffer(name)
	}
	// Close Perf Buffers
	for _, name := range m.perfbufs.Keys() {
		m.ClosePerfBuffer(name)
	}
	// Detach Raw Tracepoints
	for _, name := range m.rawtps.Keys() {
		m.DetachRawTracepoint(name)
	}
	// Detach Tracepoints
	for _, name := range m.tracepoints.Keys() {
		m.DetachTracepoint(name)
	}
	// Detach PerfEvents
	for _, name := range m.perfEvents.Keys() {
		m.DetachPerfEvent(name)
	}
	// Detach Uprobes
	for entry := range m.uprobes.IterBuffered() {
		entry.Val.Close()
		m.uprobes.Remove(entry.Key)
	}
	// Detach XDPs
	for _, name := range m.xdps.Keys() {
		m.DetachXDP(name)
	}

	// Purge Sym caches
	m.symcaches.Purge()
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

	symcaches, err := lru.NewWithEvict[int, syms.Resolver](opts.symCacheSize, func(key int, value syms.Resolver) {
		if value != nil {
			value.Cleanup()
		}
	})
	if err != nil {
		return nil, fmt.Errorf("new symbol lru cache: %w", err)
	}

	mod := &Module{
		kprobes:     cmap.New[link.Link](),
		uprobes:     cmap.New[*uprobe](),
		ringbufs:    cmap.New[*RingBuf](),
		perfbufs:    cmap.New[*PerfBuf](),
		tracepoints: cmap.New[link.Link](),
		rawtps:      cmap.New[link.Link](),
		perfEvents:  cmap.New[*PerfEvent](),
		xdps:        cmap.New[link.Link](),
		symcaches:   symcaches,
	}
	if mod.collection, err = ebpf.NewCollection(spec); err != nil {
		return nil, fmt.Errorf("ebpf new collection: %w", err)
	}
	return mod, nil
}
