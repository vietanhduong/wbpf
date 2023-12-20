package wbpf

import (
	"debug/elf"
	"errors"
	"fmt"
	"regexp"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var ErrNoSymbolsFound = fmt.Errorf("no symbols found")

type UprobeOptions struct {
	SymbolName    string
	SymbolPattern string
	Pid           int
	Offset        uint64
}

type uprobe struct {
	module string
	symbol string
	offset uint64
	link   link.Link
}

func attachUprobe(module string, prog *ebpf.Program, ret bool, opts *UprobeOptions) ([]*uprobe, error) {
	if opts == nil {
		opts = &UprobeOptions{}
	}

	if (opts.SymbolName != "" && opts.SymbolPattern != "") ||
		(opts.SymbolName == "" && opts.SymbolPattern == "") {
		return nil, fmt.Errorf("only one of symbol name or symbol pattern must be specified")
	}

	if module == "" {
		return nil, fmt.Errorf("module is required")
	}

	var fnpattern string
	if opts.SymbolPattern != "" {
		fnpattern = opts.SymbolPattern
	} else {
		fnpattern = fmt.Sprintf("^%s$", opts.SymbolName)
	}
	pattern, err := regexp.Compile(fnpattern)
	if err != nil {
		return nil, fmt.Errorf("regex compile %s: %w", fnpattern, err)
	}

	offsets, err := findSymbols(module, pattern)
	if err != nil {
		return nil, fmt.Errorf("find symbols: %w", err)
	}
	exec, err := link.OpenExecutable(module)
	// seem not possible because the findSymbols function do the same things with this function
	if err != nil {
		return nil, fmt.Errorf("link open executable %s: %w", module, err)
	}

	var attached []*uprobe

	var attachfn func(symbol string, prog *ebpf.Program, opts *link.UprobeOptions) (link.Link, error)

	if ret {
		attachfn = exec.Uretprobe
	} else {
		attachfn = exec.Uprobe
	}

	for name, addr := range offsets {
		l, err := attachfn(name, prog, &link.UprobeOptions{
			PID: opts.Pid,
			// This will make the exec not trigger the lazy symbols function
			Address: addr,
			Offset:  opts.Offset,
		})
		if err != nil {
			for _, u := range attached {
				u.Close()
			}
			return nil, fmt.Errorf("link attach uprobe: %w", err)
		}
		attached = append(attached, &uprobe{
			module: module,
			symbol: name,
			offset: addr,
			link:   l,
		})
	}

	return attached, nil
}

func findSymbols(module string, pattern *regexp.Regexp) (map[string]uint64, error) {
	f, err := elf.Open(module)
	if err != nil {
		return nil, fmt.Errorf("elf open %s: %w", module, err)
	}
	defer f.Close()

	// Loop through all symbols
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, fmt.Errorf("elf symbols: %w", err)
	}

	dynSyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, fmt.Errorf("elf dynamic symbols: %w", err)
	}

	syms = append(syms, dynSyms...)

	if len(syms) == 0 {
		return nil, ErrNoSymbolsFound
	}

	matches := make(map[string]uint64)
	for _, sym := range syms {
		// Symbol not associated with a function or other executable code.
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC || !pattern.MatchString(sym.Name) {
			continue
		}

		addr := sym.Value

		// 	Loop over ELF segments.
		for _, prog := range f.Progs {
			// Skip uninteresting segments.
			if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
				continue
			}

			if prog.Vaddr <= sym.Value && sym.Value < (prog.Vaddr+prog.Memsz) {
				// If the symbol value is contained in the segment, calculate
				// the symbol offset.
				//
				// fn symbol offset = fn symbol VA - .text VA + .text offset
				//
				// stackoverflow.com/a/40249502
				addr = sym.Value - prog.Vaddr + prog.Off
				break
			}
		}
		if addr == 0 {
			continue
		}
		matches[sym.Name] = addr
	}

	if len(matches) == 0 {
		return nil, ErrNoSymbolsFound
	}

	return matches, nil
}

func (u *uprobe) Close() {
	if u == nil || u.link == nil {
		return
	}
	u.link.Close()
}

func (u *uprobe) keygen() string {
	if u == nil {
		return ""
	}
	return fmt.Sprintf("%s_%s_0x%x", u.module, u.symbol, u.offset)
}
