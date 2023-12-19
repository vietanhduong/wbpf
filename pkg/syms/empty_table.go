package syms

type emptyTable struct{}

func (*emptyTable) Resolve(uint64) string { return "" }
func (*emptyTable) Cleanup()              {}
func (*emptyTable) IsDead() bool          { return false }
func (*emptyTable) Size() int             { return 0 }
