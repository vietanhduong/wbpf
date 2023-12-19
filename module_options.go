package wbpf

type moduleOptions struct {
	file         string
	content      []byte
	symCacheSize int
}

type ModuleOption func(*moduleOptions)

func WithElfFile(path string) ModuleOption {
	return func(mo *moduleOptions) {
		mo.file = path
	}
}

func WithElfFileContent(content []byte) ModuleOption {
	return func(mo *moduleOptions) {
		mo.content = content[:]
	}
}

func WithSymCacheSize(size int) ModuleOption {
	return func(mo *moduleOptions) {
		if size > 0 {
			mo.symCacheSize = size
		}
	}
}

func defaultModuleOpts() *moduleOptions {
	return &moduleOptions{
		symCacheSize: 10000,
	}
}
