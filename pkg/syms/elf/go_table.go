package elf

import (
	"debug/elf"
	"errors"
	"fmt"

	gosym2 "github.com/vietanhduong/wbpf/pkg/syms/gosym"
	"github.com/vietanhduong/wbpf/pkg/utils"
)

type GoTable struct {
	Index          gosym2.FlatFuncIndex
	File           *MMapedElfFile
	gopclnSection  elf.SectionHeader
	funcNameOffset uint64
	fallback       Table
}

func (g *GoTable) IsDead() bool {
	return g.File.err != nil
}

func (g *GoTable) DebugInfo() SymTabDebugInfo {
	return SymTabDebugInfo{
		Name: fmt.Sprintf("GoTableWithFallback %p ", g),
		Size: g.Size(),
		File: g.File.fpath,
	}
}

func (g *GoTable) Size() int {
	return len(g.Index.Name) + g.fallback.Size()
}

func (g *GoTable) Refresh() {}

func (g *GoTable) Resolve(addr uint64) string {
	if sym := g.resolve(addr); sym != "" {
		return sym
	}
	return g.fallback.Resolve(addr)
}

func (g *GoTable) resolve(addr uint64) string {
	n := len(g.Index.Name)
	if n == 0 {
		return ""
	}
	if addr >= g.Index.End {
		return ""
	}
	i := g.Index.Entry.FindIndex(addr)
	if i == -1 {
		return ""
	}
	name, _ := g.goSymbolName(i)
	return name
}

func (g *GoTable) Cleanup() {
	g.File.Close()
	g.fallback.Cleanup()
}

var (
	errEmptyText         = errors.New("empty .text")
	errGoPCLNTabNotFound = errors.New(".gopclntab not found")
	errGoTooOld          = errors.New("gosymtab: go sym tab too old")
	errGoParseFailed     = errors.New("gosymtab: go sym tab parse failed")
	errGoFailed          = errors.New("gosymtab: go sym tab  failed")
	errGoOOB             = fmt.Errorf("go table oob")
	errGoSymbolsNotFound = errors.New("gosymtab: no go symbols found")
)

func (f *MMapedElfFile) NewGoTable(fallback Table) (*GoTable, error) {
	obj := f
	var err error
	text := obj.Section(".text")
	if text == nil {
		return nil, errEmptyText
	}
	pclntab := obj.Section(".gopclntab")
	if pclntab == nil {
		return nil, errGoPCLNTabNotFound
	}
	if f.fd == nil {
		return nil, fmt.Errorf("elf file not open")
	}

	pclntabReader := gosym2.NewFilePCLNData(f.fd, int(pclntab.Offset))

	pclntabHeader := make([]byte, 64)
	if err = pclntabReader.ReadAt(pclntabHeader, 0); err != nil {
		return nil, err
	}

	textStart := gosym2.ParseRuntimeTextFromPclntab18(pclntabHeader)

	if textStart == 0 {
		// for older versions text.Addr is enough
		// https://github.com/golang/go/commit/b38ab0ac5f78ac03a38052018ff629c03e36b864
		textStart = text.Addr
	}
	if textStart < text.Addr || textStart >= text.Addr+text.Size {
		return nil, fmt.Errorf(" runtime.text out of .text bounds %d %d %d", textStart, text.Addr, text.Size)
	}
	pcln := gosym2.NewLineTableStreaming(pclntabReader, textStart)

	if !pcln.IsGo12() {
		return nil, errGoTooOld
	}
	if pcln.IsFailed() {
		return nil, errGoParseFailed
	}
	funcs := pcln.Go12Funcs()
	if len(funcs.Name) == 0 || funcs.Entry.Length() == 0 || funcs.End == 0 {
		return nil, errGoSymbolsNotFound
	}

	if funcs.Entry.Length() != len(funcs.Name) {
		return nil, errGoParseFailed // this should not happen
	}

	if utils.IsNil(fallback) {
		fallback = &emptyFallback{}
	}

	funcNameOffset := pcln.FuncNameOffset()
	return &GoTable{
		Index:          funcs,
		File:           f,
		gopclnSection:  *pclntab,
		funcNameOffset: funcNameOffset,
		fallback:       fallback,
	}, nil
}

func (g *GoTable) SetFallback(fallback Table) {
	if !utils.IsNil(fallback) {
		g.fallback = fallback
	}
}

func (g *GoTable) goSymbolName(idx int) (string, error) {
	offsetGpcln := g.gopclnSection.Offset
	if idx >= len(g.Index.Name) {
		return "", errGoOOB
	}

	offsetName := g.Index.Name[idx]
	name, ok := g.File.getString(int(offsetGpcln)+int(g.funcNameOffset)+int(offsetName), nil)
	if !ok {
		return "", errGoFailed
	}
	return name, nil
}
