package syms

import (
	"github.com/sirupsen/logrus"
	"github.com/vietanhduong/wbpf/pkg/logging"
	"github.com/vietanhduong/wbpf/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithFields(logrus.Fields{logfields.LogSubsys: "syms"})

type Resolver interface {
	Resolve(addr uint64) Symbol
	Cleanup()
	Refresh()
}

func NewResolver(pid int, opts *SymbolOptions) (Resolver, error) {
	if pid < 0 {
		return NewKernSym()
	}
	return NewProcSymbol(pid, opts)
}

type EmptyResolver struct{}

var _ Resolver = (*EmptyResolver)(nil)

func (*EmptyResolver) Resolve(uint64) Symbol { return Symbol{} }
func (*EmptyResolver) Cleanup()              {}
func (*EmptyResolver) Refresh()              {}
