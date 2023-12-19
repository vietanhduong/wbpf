package syms

import (
	"fmt"
	"slices"

	"github.com/vietanhduong/wbpf/pkg/proc"
)

type mrange struct {
	procmap *proc.Map
	module  *ProcModule
}

type ProcSymbol struct {
	pid     int
	opts    *SymbolOptions
	modules map[proc.File]*ProcModule
	ranges  []mrange
	stats   *proc.Stat
}

func NewProcSymbol(pid int, opts *SymbolOptions) (*ProcSymbol, error) {
	if opts == nil {
		opts = defaultSymbolOpts
	}
	this := &ProcSymbol{
		pid:     pid,
		opts:    opts,
		modules: make(map[proc.File]*ProcModule),
	}
	var err error
	if this.stats, err = proc.ProcStat(pid); err != nil {
		return nil, fmt.Errorf("proc stats: %w", err)
	}
	if err = this.load(); err != nil {
		return nil, fmt.Errorf("load: %w", err)
	}
	return this, nil
}

func (s *ProcSymbol) Refresh() {
	for i := range s.ranges {
		s.ranges[i].module = nil
	}
	s.ranges = s.ranges[:0]
	if err := s.load(); err != nil {
		log.Errorf("Failed to refresh symbol: %v", err)
	}
}

func (s *ProcSymbol) Resolve(addr uint64) Symbol {
	if s.stats.IsStale() {
		s.Refresh()
	}
	if addr == 0xcccccccccccccccc || addr == 0x9090909090909090 {
		return Symbol{Start: 0, Name: "end_of_stack", Module: "[unknown]"}
	}
	i, found := slices.BinarySearchFunc(s.ranges, addr, binarySearchRange)
	if !found {
		return Symbol{}
	}
	r := s.ranges[i]
	t := r.module
	if t == nil {
		return Symbol{}
	}
	sym := t.Resolve(addr)
	modoffset := addr - t.base
	if sym == "" {
		return Symbol{Start: modoffset, Module: r.procmap.Pathname}
	}

	return Symbol{Start: modoffset, Name: sym, Module: r.procmap.Pathname}
}

func (s *ProcSymbol) load() error {
	maps, err := proc.ParseProcMaps(s.pid)
	if err != nil {
		return fmt.Errorf("parse proc map: %w", err)
	}
	keeps := make(map[proc.File]struct{})
	for _, m := range maps {
		s.ranges = append(s.ranges, mrange{procmap: m})
		r := &s.ranges[len(s.ranges)-1]
		if m := s.getModule(r); m != nil {
			r.module = m
			keeps[r.procmap.File()] = struct{}{}
		}
	}

	var remove []proc.File
	for f := range s.modules {
		if _, keep := keeps[f]; !keep {
			remove = append(remove, f)
		}
	}
	for _, f := range remove {
		if m := s.modules[f]; m != nil {
			m.Cleanup()
		}
		delete(s.modules, f)
	}
	return nil
}

func (s *ProcSymbol) getModule(r *mrange) *ProcModule {
	f := r.procmap.File()
	m, ok := s.modules[f]
	if !ok {
		m = s.createModule(r.procmap)
		s.modules[f] = m
	}
	return m
}

func (s *ProcSymbol) createModule(m *proc.Map) *ProcModule {
	path := newProcPath(m.Pathname, s.pid, s.stats.GetRootFD(), m.InMem && s.pid != -1)
	return NewProcModule(m.Pathname, m, path, s.opts)
}

func (s *ProcSymbol) Cleanup() {
	for _, t := range s.modules {
		t.Cleanup()
	}
	clear(s.modules)
}

func binarySearchRange(e mrange, addr uint64) int {
	if addr < e.procmap.StartAddr {
		return 1
	}
	if addr >= e.procmap.EndAddr {
		return -1
	}
	return 0
}
