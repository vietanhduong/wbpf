package elf

type Table interface {
	Resolve(addr uint64) string
	Size() int
	Cleanup()
}

type emptyFallback struct{}

func (*emptyFallback) Resolve(uint64) string { return "" }
func (*emptyFallback) Size() int             { return 0 }
func (*emptyFallback) Cleanup()              {}
