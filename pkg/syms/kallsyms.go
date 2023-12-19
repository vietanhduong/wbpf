package syms

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

func parseKallsyms(path string) ([]Symbol, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("os read file %s: %w", path, err)
	}
	defer f.Close()
	var ret []Symbol
	var kernelAddr uint64 = 0
	if runtime.GOARCH == "amd64" {
		// https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
		kernelAddr = 0x00ffffffffffffff
	}
	for {
		var sym Symbol
		var perm, module string
		n, _ := fmt.Fscanf(f, "%x %1s %s %s\n", &sym.Start, &perm, &sym.Name, &module)
		if n != 4 && n != 3 {
			break
		}

		if sym.Start == 0 || sym.Start < kernelAddr {
			continue
		}

		if perm == "b" || perm == "B" ||
			perm == "d" || perm == "D" ||
			perm == "r" || perm == "R" {
			continue
		}

		sym.Module = "kernel"

		if module = strings.TrimSpace(module); module != "" &&
			module[0] == '[' &&
			module[len(module)-1] == ']' {
			sym.Module = module[1 : len(module)-1]
		}
		ret = append(ret, sym)
	}
	return ret, nil
}
