package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vietanhduong/wbpf"
	"github.com/vietanhduong/wbpf/pkg/logging"
	"golang.org/x/sys/unix"
)

/*
struct stack_t {
  __u32 pid;
  __s64 user_stack_id;
  __s64 kernel_stack_id;
};
*/

type stack struct {
	pid         uint32
	_           [4]byte // padding
	userstack   int64
	kernelstack int64
}

func (st *stack) String() string {
	if st == nil {
		return ""
	}

	return fmt.Sprintf("pid=%d user=0x%08x kernel=0x%08x", st.pid, st.userstack, st.kernelstack)
}

//go:embed profiler.bpf.o
var elfcontent []byte

func main() {
	var pid int
	var sampleRate int
	var pollPeriod time.Duration
	var loglevel string
	flag.IntVar(&pid, "pid", -1, "Target observe Process ID")
	flag.IntVar(&sampleRate, "sample-rate", 49, "Sample rate (unit Hz). Should be 49, 99.")
	flag.DurationVar(&pollPeriod, "poll-period", 30*time.Second, "The duration between polling data from epoll.")
	flag.StringVar(&loglevel, "log-level", "info", "Log level.")
	flag.Parse()

	logging.SetupLogging(logging.WithLogLevel(loglevel))

	log := logging.DefaultLogger.WithField("example", "profiler")

	if pid == -1 {
		log.Errorf("No pid is specified")
		os.Exit(1)
	}

	if len(elfcontent) == 0 {
		log.Errorf("ERR: no elf object which is embeded, please run `make build-profiler` first")
		os.Exit(1)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Errorf("ERR: Failed to acquire memory lock: %v", err)
		os.Exit(1)
	}

	mod, err := wbpf.NewModule(wbpf.WithElfFileContent(elfcontent))
	if err != nil {
		log.Errorf("ERR: Failed to new module: %v", err)
		os.Exit(1)
	}
	defer mod.Close()

	stacktraces, err := mod.GetTable("stack_traces")
	if err != nil {
		log.Errorf("ERR: Failed to get stack_traces table: %v", err)
		os.Exit(1)
	}

	uresolver := func(addr uint64) string {
		return mod.ResolveSymbol(pid, addr, wbpf.ResolveSymbolOptions{})
	}

	kresolver := func(addr uint64) string {
		return mod.ResolveKernelSymbol(addr, wbpf.ResolveSymbolOptions{})
	}

	processStackTrace := func(st *stack) {
		if st.pid != uint32(pid) {
			return
		}
		var ret string
		if st.userstack > 0 {
			ret += buildstack(stacktraces.GetStackAddr(st.userstack, false), uresolver, "")
		}
		if ret != "" {
			ret += ";"
		}
		if st.kernelstack > 0 {
			ret += buildstack(stacktraces.GetStackAddr(st.kernelstack, false), kresolver, "[k] ")
		}
		if ret != "" {
			log.Infof(ret)
		}
	}

	err = mod.OpenRingBuffer("histogram", &wbpf.RingBufOptions{
		Callback: func(raw []byte) { processStackTrace((*stack)(unsafe.Pointer(&raw[0]))) },
	})
	if err != nil {
		log.Errorf("ERR: Failed to open ring buffer histogram: %v", err)
		os.Exit(1)
	}

	err = mod.AttachPerfEvent("do_perf_event", wbpf.PerfEventOptions{
		Type:       unix.PERF_TYPE_SOFTWARE,
		Config:     unix.PERF_COUNT_SW_CPU_CLOCK,
		SampleRate: uint64(sampleRate),
	})
	if err != nil {
		log.Errorf("ERR: Failed to attach perf event: %v", err)
		os.Exit(1)
	}
	log.Infof("Attached perf event!")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGKILL)
	defer cancel()

	tick := time.NewTicker(pollPeriod)

	log.Infof("Starting profiler...")
	for {
		select {
		case <-ctx.Done():
			mod.PollRingBuffer("histogram", 0)
			return
		case <-tick.C:
			mod.PollRingBuffer("histogram", 0)
		}
	}
}

func buildstack(addrs []uint64, resolve func(addr uint64) string, prefix string) string {
	var ret string
	begin := len(addrs) - 1
	for i := begin; i >= 0; i-- {
		addr := addrs[i]
		if addr == 0xcccccccccccccccc && addr == addrs[begin] {
			continue
		}
		symbol := resolve(addr)
		ret = fmt.Sprintf("%s%s%s%s", ret, prefix, symbol, ";")
	}
	if ret != "" {
		ret = strings.TrimSuffix(ret, ";")
	}
	return ret
}
