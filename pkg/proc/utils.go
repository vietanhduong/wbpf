package proc

import (
	"strings"

	"golang.org/x/sys/unix"
)

func IsPerfMap(path string) bool {
	return strings.HasSuffix(path, ".map")
}

func IsValidPerfMap(path string) bool {
	return IsPerfMap(path) && unix.Access(path, unix.R_OK) == nil
}

func IsVDSO(name string) bool { return name == "[vdso]" }
