package wbpf

import (
	"runtime"
	"strings"
)

func GetSyscallPrefix() string {
	switch runtime.GOARCH {
	case "amd64":
		return "__x64_sys_"
	case "arm64":
		return "__arm64_sys_"
	case "s390x":
		return "__s390x_sys_"
	case "s390":
		return "__s390_sys_"
	}
	return "sys_"
}

func GetSyscallName(name string) string {
	if strings.HasPrefix(name, GetSyscallPrefix()) {
		return name
	}
	return GetSyscallPrefix() + name
}

var syscallPrefixes = []string{
	"sys_",
	"__x64_sys_",
	"__x32_compat_sys_",
	"__ia32_compat_sys_",
	"__arm64_sys_",
	"__s390x_sys_",
	"__s390_sys_",
}

func FixSyscallName(name string) string {
	for _, p := range syscallPrefixes {
		if strings.HasPrefix(name, p) {
			return GetSyscallName(name[len(p):])
		}
	}
	return name
}
