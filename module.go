package wbpf

import (
	"bytes"
	"errors"
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
	"golang.org/x/sys/unix"
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
	tracings    cmap.ConcurrentMap[string, link.Link]
	lsms        cmap.ConcurrentMap[string, link.Link]

	symcaches *lru.Cache[int, syms.Resolver]
}

// NewModule creates a new eBPF module from the given file or content.
// Only one of file or content must be specified.
// Returns:
// - The module
// - A function that must be called after attaching the Collection's entrypoint
// programs to their respective hooks
// - An error if the module could not be created
func NewModule(opts ...ModuleOption) (*Module, func() error, error) {
	modOpts := defaultModuleOpts()
	for _, opt := range opts {
		opt(modOpts)
	}

	if (modOpts.file == "" && len(modOpts.content) == 0) ||
		(modOpts.file != "" && len(modOpts.content) != 0) {
		return nil, nil, fmt.Errorf("only one of file or content must be specified")
	}
	mod, commit, err := newModule(modOpts)
	if err != nil {
		return nil, nil, err
	}
	runtime.SetFinalizer(mod, func(m *Module) { m.Close() })
	return mod, commit, nil
}

// GetTable returns the table with the given name.
// Otherwise, an error will be returned.
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
func (m *Module) AttachKprobe(sysname, prog string) (link.Link, error) {
	return m.attachKprobe(sysname, prog, false)
}

// DetachKprobe detaches the kprobe with the given name. If the input prog is empty,
// all kprobes with the given name will be detached.
func (m *Module) DetachKprobe(sysname, prog string) {
	detach := func(name string) {
		if prog == "" {
			detachPrefix(fmt.Sprintf("%s~", name), m.kprobes)
			return
		}
		detach(fmt.Sprintf("%s~%s", name, prog), m.kprobes)
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
func (m *Module) AttachKretprobe(sysname, prog string) (link.Link, error) {
	return m.attachKprobe(sysname, prog, true)
}

// AttachTracepoint attaches a tracepoint to the input prog.
// The input name must be in the format 'group:name'
func (m *Module) AttachTracepoint(name, prog string) (link.Link, error) {
	key := fmt.Sprintf("%s~%s", name, prog)
	if l, ok := m.tracepoints.Get(key); ok {
		return l, nil
	}
	parts := strings.SplitN(name, ":", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid tracepoint name, expected %q but got %q", "<group>:<name>", name)
	}

	p, err := m.GetProg(prog)
	if err != nil {
		return nil, fmt.Errorf("getting program %s: %w", prog, err)
	}

	l, err := link.Tracepoint(parts[0], parts[1], p, nil)
	if err != nil {
		return nil, fmt.Errorf("attaching tracepoint: %w", err)
	}
	m.tracepoints.Set(key, l)
	return l, nil
}

// DetachTracepoint detaches the tracepoint with the given name.
// The input name must be in the format 'group:name'. If the input prog is empty,
// all tracepoints with the given name will be detached.
func (m *Module) DetachTracepoint(name, prog string) {
	if prog == "" {
		detachPrefix(fmt.Sprintf("%s~", name), m.tracepoints)
		return
	}
	detach(fmt.Sprintf("%s~%s", name, prog), m.tracepoints)
}

// AttachRawTracepoint attaches a raw tracepoint to the input prog.
// The input name is in the format 'name', there is no group.
func (m *Module) AttachRawTracepoint(name, prog string) (link.Link, error) {
	key := fmt.Sprintf("%s~%s", name, prog)
	if l, ok := m.rawtps.Get(key); ok {
		return l, nil
	}

	p, err := m.GetProg(prog)
	if err != nil {
		return nil, fmt.Errorf("getting program %s: %w", prog, err)
	}

	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: name, Program: p})
	if err != nil {
		return nil, fmt.Errorf("attaching raw tracepoint %s: %w", name, err)
	}
	m.rawtps.Set(key, l)
	return l, nil
}

// DetachRawTracepoint detaches the raw tracepoint with the given name and prog.
// The input name is in the format 'name', there is no group. If the input prog
// is empty, all raw tracepoints with the given name will be detached.
func (m *Module) DetachRawTracepoint(name, prog string) {
	if prog == "" {
		detachPrefix(fmt.Sprintf("%s~", name), m.rawtps)
		return
	}
	detach(fmt.Sprintf("%s~%s", name, prog), m.rawtps)
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

func (m *Module) DetachPerfEvent(prog string) { detach(prog, m.perfEvents) }

func (m *Module) attachKprobe(sysname, prog string, ret bool) (link.Link, error) {
	key := fmt.Sprintf("%s~%s", sysname, prog)
	if ret {
		key = fmt.Sprintf("%s~ret", sysname)
	}
	if l, ok := m.kprobes.Get(key); ok {
		return l, nil
	}

	p, err := m.GetProg(prog)
	if err != nil {
		return nil, fmt.Errorf("getting prog %s: %w", prog, err)
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

	l, err := fn(sysname, p, nil)
	if err != nil {
		return nil, fmt.Errorf("attaching kprobe %s (%s): %w", fnname, sysname, err)
	}
	m.kprobes.Set(key, l)
	return l, nil
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
func (m *Module) AttachXDP(ifname, prog string, flags uint64) (link.Link, error) {
	key := fmt.Sprintf("%s~%s", ifname, prog)
	if l, ok := m.xdps.Get(key); ok {
		return l, nil
	}
	p, err := m.GetProg(prog)
	if err != nil {
		return nil, fmt.Errorf("getting program %s: %w", prog, err)
	}

	i, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("getting network interface: %w", err)
	}
	log.Tracef("Found interface %s at index: %d", i.Name, i.Index)

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   p,
		Interface: i.Index,
		Flags:     link.XDPAttachFlags(flags),
	})
	if err != nil {
		return nil, fmt.Errorf("attaching xdp: %w", err)
	}
	m.xdps.Set(key, l)
	return l, nil
}

// DetachXDP detaches the XDP program from the given interface. If the input prog is empty,
// all XDP programs attached to the given interface will be detached.
func (m *Module) DetachXDP(ifname, prog string) {
	if prog == "" { // remove all with the given ifname
		detachPrefix(fmt.Sprintf("%s~", ifname), m.xdps)
		return
	}
	detach(fmt.Sprintf("%s~%s", ifname, prog), m.xdps)
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
		return fmt.Errorf("getting table: %w", err)
	}

	buf, err := NewRingBuf(tbl, opts)
	if err != nil {
		return fmt.Errorf("creating ringbuf: %w", err)
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

func (m *Module) AttachFExit(prog string) (link.Link, error) {
	return m.AttachTracing(prog, ebpf.AttachTraceFExit)
}

func (m *Module) AttachFEntry(prog string) (link.Link, error) {
	return m.AttachTracing(prog, ebpf.AttachTraceFEntry)
}

func (m *Module) AttachModifyReturn(prog string) (link.Link, error) {
	return m.AttachTracing(prog, ebpf.AttachModifyReturn)
}

// AttachLSM links a Linux security module (LSM) BPF Program to a BPF
// hook defined in kernel modules.
func (m *Module) AttachLSM(prog string) (link.Link, error) {
	if l, ok := m.lsms.Get(prog); ok {
		return l, nil
	}

	p, err := m.GetProg(prog)
	if err != nil {
		return nil, fmt.Errorf("getting program %s: %w", prog, err)
	}

	l, err := link.AttachLSM(link.LSMOptions{Program: p})
	if err != nil {
		return nil, fmt.Errorf("attaching lsm: %w", err)
	}

	m.lsms.Set(prog, l)
	return l, err
}

// AttachTracing links a tracing (fentry/fexit/fmod_ret) BPF program or
// a BTF-powered raw tracepoint (tp_btf) BPF Program to a BPF hook defined
// in kernel modules.
func (m *Module) AttachTracing(prog string, typ ebpf.AttachType) (link.Link, error) {
	key := fmt.Sprintf("%s~%s", prog, typ.String())
	if l, ok := m.tracings.Get(key); ok {
		return l, nil
	}

	p, err := m.GetProg(prog)
	if err != nil {
		return nil, fmt.Errorf("getting program %s: %w", prog, err)
	}

	tp, err := link.AttachTracing(link.TracingOptions{
		Program:    p,
		AttachType: typ,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching tracing (type=%s): %w", typ.String(), err)
	}
	m.tracings.Set(key, tp)
	return tp, nil
}

func (m *Module) DetachTracing(prog string, typ ebpf.AttachType) {
	if typ == ebpf.AttachNone {
		detachPrefix(fmt.Sprintf("%s~", prog), m.tracings)
		return
	}
	detach(fmt.Sprintf("%s~%s", prog, typ.String()), m.tracings)
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

// Programs return all programs in the collection
func (m *Module) Programs() map[string]*ebpf.Program {
	return m.collection.Programs
}

// Maps return all the maps in the collection
func (m *Module) Maps() map[string]*ebpf.Map {
	return m.collection.Maps
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
	for _, key := range m.kprobes.Keys() {
		detach(key, m.kprobes)
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
	for _, key := range m.rawtps.Keys() {
		detach(key, m.rawtps)
	}
	// Detach Tracepoints
	for _, key := range m.tracepoints.Keys() {
		detach(key, m.tracepoints)
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
	for _, key := range m.xdps.Keys() {
		detach(key, m.xdps)
	}
	// Detach Tracings
	for _, key := range m.tracings.Keys() {
		detach(key, m.tracings)
	}

	// Detach LSMs
	for _, key := range m.lsms.Keys() {
		detach(key, m.lsms)
	}

	// Purge Sym caches
	m.symcaches.Purge()
}

func newModule(opts *moduleOptions) (*Module, func() error, error) {
	if opts.file != "" {
		buf, err := os.ReadFile(opts.file)
		if err != nil {
			return nil, nil, fmt.Errorf("os read file: %w", err)
		}
		opts.content = buf
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(opts.content))
	if err != nil {
		return nil, nil, fmt.Errorf("ebpf load collection spec: %w", err)
	}

	symcaches, err := lru.NewWithEvict[int, syms.Resolver](opts.symCacheSize, func(key int, value syms.Resolver) {
		if value != nil {
			value.Cleanup()
		}
	})
	if err != nil {
		return nil, nil, fmt.Errorf("new symbol lru cache: %w", err)
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
		tracings:    cmap.New[link.Link](),
		lsms:        cmap.New[link.Link](),
		symcaches:   symcaches,
	}

	mod.collection, err = ebpf.NewCollectionWithOptions(spec, opts.collectionOptions)
	var toReplace []string
	// Handle incompatible maps
	// Collect key names of maps that are not compatible with their pinned
	// counterparts and remove their pinning flags.
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		var incompatible []string
		incompatible, err = incompatibleMaps(spec, opts.collectionOptions)
		if err != nil {
			return nil, nil, fmt.Errorf("finding incompatible maps: %w", err)
		}
		toReplace = append(toReplace, incompatible...)

		// Retry loading the Collection with necessary pinning flags removed.
		mod.collection, err = ebpf.NewCollectionWithOptions(spec, opts.collectionOptions)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("ebpf new collection: %w", err)
	}

	// Collect Maps that need their bpffs pins replaced. Pull out Map objects
	// before returning the Collection, since commit() still needs to work when
	// the Map is removed from the Collection, e.g. by [ebpf.Collection.Assign].
	pins, err := mapsToReplace(toReplace, spec, mod.collection, opts.collectionOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("collecting map pins to replace: %w", err)
	}

	// Load successful, return a function that must be invoked after attaching the
	// Collection's entrypoint programs to their respective hooks.
	commit := func() error {
		return commitMapPins(pins)
	}
	return mod, commit, nil
}

func detach[T interface{ Close() error }](key string, m cmap.ConcurrentMap[string, T]) {
	if v, _ := m.Get(key); !utils.IsNil(v) {
		v.Close()
	}
	m.Remove(key)
}

func detachPrefix[T interface{ Close() error }](prefix string, m cmap.ConcurrentMap[string, T]) {
	for _, k := range m.Keys() {
		if strings.HasPrefix(k, prefix) {
			detach(k, m)
		}
	}
}

// incompatibleMaps returns the key names MapSpecs in spec with the
// LIBBPF_PIN_BY_NAME pinning flag that are incompatible with their pinned
// counterparts. Removes the LIBBPF_PIN_BY_NAME flag. opts.Maps.PinPath must be
// specified.
//
// The slice of strings returned contains the keys used in Collection.Maps and
// CollectionSpec.Maps, which can differ from the Map's Name field.
func incompatibleMaps(spec *ebpf.CollectionSpec, opts ebpf.CollectionOptions) ([]string, error) {
	if opts.Maps.PinPath == "" {
		return nil, errors.New("missing opts.Maps.PinPath")
	}

	var incompatible []string
	for key, ms := range spec.Maps {
		if ms.Pinning != ebpf.PinByName {
			continue
		}

		pinPath := path.Join(opts.Maps.PinPath, ms.Name)
		m, err := ebpf.LoadPinnedMap(pinPath, nil)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("opening map %s from pin: %w", ms.Name, err)
		}

		if ms.Compatible(m) == nil {
			m.Close()
			continue
		}

		incompatible = append(incompatible, key)
		ms.Pinning = 0
	}

	return incompatible, nil
}
