package main

import (
	"log"
	"os"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vietanhduong/wbpf"
)

//go:generate clang -g -O2 -target bpf -c kprobe.bpf.h -o kprobe.bpf.o -D__TARGET_ARCH_x86 -mcpu=v1 -I ../headers/vmlinux -I ../headers/libbpf

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("ERR: Failed to acquire memory lock: %v", err)
		os.Exit(1)
	}

	mod, err := wbpf.NewModule(wbpf.WithElfFile("./kprobe.bpf.o"))
	if err != nil {
		log.Printf("ERR: Failed to new module: %v", err)
		os.Exit(1)
	}
	defer mod.Close()
	if err := mod.AttackKprobe(wbpf.GetSyscallName("execve"), "exec"); err != nil {
		log.Printf("ERR: Failed attach kprobe execve: %v", err)
		os.Exit(1)
	}
	if err := mod.AttackKprobe("disassociate_ctty", "disassociate_ctty"); err != nil {
		log.Printf("ERR: Failed attach kprobe disassociate_ctty: %v", err)
		os.Exit(1)
	}
}
