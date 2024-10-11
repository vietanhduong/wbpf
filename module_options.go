package wbpf

import "github.com/cilium/ebpf"

type moduleOptions struct {
	file              string
	content           []byte
	symCacheSize      int
	collectionOptions ebpf.CollectionOptions
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

func WithCollectionOptions(opts ebpf.CollectionOptions) ModuleOption {
	return func(mo *moduleOptions) {
		mo.collectionOptions = opts
	}
}

func defaultModuleOpts() *moduleOptions {
	return &moduleOptions{
		symCacheSize: 10000,
	}
}
