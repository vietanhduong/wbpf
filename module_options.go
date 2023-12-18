package wbpf

type moduleOptions struct {
	file    string
	content []byte
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
