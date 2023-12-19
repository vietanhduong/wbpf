package syms

import (
	"github.com/ianlancetaylor/demangle"
)

type SymbolTable interface {
	Resolve(addr uint64) string
	Cleanup()
	IsDead() bool
	Size() int
}

type SymbolOptions struct {
	DemangleType DemangleType
	UseDebugFile bool
}

type DemangleType string

const (
	DemangleNone       DemangleType = "NONE"
	DemangleSimplified DemangleType = "SIMPLIFIED"
	DemangleTemplates  DemangleType = "TEMPLATES"
	DemangleFull       DemangleType = "FULL"
)

var defaultSymbolOpts = &SymbolOptions{
	DemangleType: DemangleFull,
	UseDebugFile: false,
}

func (dt DemangleType) ToOptions() []demangle.Option {
	switch dt {
	case DemangleNone:
		return nil
	case DemangleSimplified:
		return []demangle.Option{demangle.NoParams, demangle.NoEnclosingParams, demangle.NoTemplateParams}
	case DemangleTemplates:
		return []demangle.Option{demangle.NoParams, demangle.NoEnclosingParams}
	default:
		return []demangle.Option{demangle.NoClones}
	}
}

type ProcModuleType string

const (
	UNKNOWN ProcModuleType = "UNKNOWN"
	EXEC    ProcModuleType = "EXEC"
	SO      ProcModuleType = "SO"
	VDSO    ProcModuleType = "VDSO"
)

type Symbol struct {
	Start  uint64 `json:"start,omitempty"`
	Name   string `json:"name,omitempty"`
	Module string `json:"module,omitempty"`
}
