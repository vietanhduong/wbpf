package main

import (
	"context"
	_ "embed"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vietanhduong/wbpf"
)

type op uint32

/*
#define OP_PID_UNKNOWN 0
#define OP_PID_DEAD 1
#define OP_PID_EXEC 2
*/
const (
	unknown op = iota
	dead
	exec
)

func (o op) String() string {
	switch o {
	case dead:
		return "dead"
	case exec:
		return "exec"
	}
	return "unknown"
}

type pidevent struct {
	pid uint32
	op  op
}

//go:embed kprobe.bpf.o
var elfcontent []byte

func main() {
	if len(elfcontent) == 0 {
		log.Printf("ERR: no elf object which is embeded, please run `make build-kprobe` first")
		os.Exit(1)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("ERR: Failed to acquire memory lock: %v", err)
		os.Exit(1)
	}

	mod, err := wbpf.NewModule(wbpf.WithElfFileContent(elfcontent))
	if err != nil {
		log.Printf("ERR: Failed to new module: %v", err)
		os.Exit(1)
	}
	defer mod.Close()
	if err := mod.AttackKprobe(wbpf.GetSyscallName("execve"), "exec"); err != nil {
		log.Printf("ERR: Failed attach kprobe execve: %v", err)
		os.Exit(1)
	}

	if err := mod.AttackKprobe(wbpf.GetSyscallName("execveat"), "exec"); err != nil {
		log.Printf("ERR: Failed attach kprobe execve: %v", err)
		os.Exit(1)
	}

	if err := mod.AttackKprobe("disassociate_ctty", "disassociate_ctty"); err != nil {
		log.Printf("ERR: Failed attach kprobe disassociate_ctty: %v", err)
		os.Exit(1)
	}

	err = mod.OpenRingBuffer("pid_events", &wbpf.RingBufOptions{
		Callback: func(raw []byte) {
			event := (*pidevent)(unsafe.Pointer(&raw[0]))
			log.Printf("Event: pid=%d op=%s", event.pid, event.op.String())
		},
	})
	if err != nil {
		log.Printf("ERR: Failed to open ring buffer pid_events: %v", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGKILL)
	defer cancel()

	tick := time.NewTicker(5 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			mod.PollRingBuffer("pid_events", 0)
		}
	}
}
