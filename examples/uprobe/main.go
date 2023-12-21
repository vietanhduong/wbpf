package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"path"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	_ "embed"

	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	"github.com/vietanhduong/wbpf"
	"github.com/vietanhduong/wbpf/pkg/logging"
	"golang.org/x/sys/unix"
)

//go:embed uprobe.bpf.o
var elfcontent []byte

/*
	struct event {
	  __u8 method[16];
	  __u8 host[128];
	  __u8 path[128];
	  __u8 query[128];
	};
*/
type event struct {
	method [16]byte
	host   [128]byte
	path   [128]byte
	query  [256]byte
}

var log = logging.DefaultLogger.WithFields(logrus.Fields{"example": "uprobe"})

func main() {
	var loglevel string
	flag.StringVar(&loglevel, "log-level", "info", "Log Level.")
	flag.Parse()

	logging.SetupLogging(logging.WithLogLevel(loglevel))

	if len(elfcontent) == 0 {
		log.Errorf("no elf object which is embeded, please run `make build-uprobe` first")
		os.Exit(1)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Errorf("failed to unlock memory: %v", err)
		os.Exit(1)
	}

	mod, err := wbpf.NewModule(wbpf.WithElfFileContent(elfcontent))
	if err != nil {
		log.Errorf("failed to init wbpf module %v", err)
		os.Exit(1)
	}
	defer mod.Close()

	// open perf buffer
	err = mod.OpenPerfBuffer("events", &wbpf.PerfBufOptions{
		RawCallback: func(raw []byte) {
			event := (*event)(unsafe.Pointer(&raw[0]))
			log.WithFields(logrus.Fields{
				"method": cstring(event.method[:]),
				"host":   cstring(event.host[:]),
				"path":   cstring(event.path[:]),
				"query":  cstring(event.query[:]),
			}).Info()
		},
		Async:         true,
		PerCPUBufSize: 1024 * 1024,
	})
	if err != nil {
		log.Errorf("failed to open perf buffer: %v", err)
		os.Exit(1)
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		log.Errorf("unable to determine current package path")
		os.Exit(1)
	}

	binaryPath := path.Join(path.Dir(filename), "test-app/test-app")
	// attach uprobe
	err = mod.AttachUprobe(binaryPath, "main_handler", &wbpf.UprobeOptions{
		SymbolName: "main.handler",
		Pid:        -1, // all process
	})
	if err != nil {
		log.Errorf("failed to attach uprobe (bin=%s): %v", binaryPath, err)
		os.Exit(1)
	}
	log.Infof("attached uretprobe to test-app to main.handler symbol")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGILL)
	defer cancel()

	tick := time.NewTicker(time.Second)
	for {
		select {
		case <-ctx.Done():
			mod.PollPerfBuffer("events", 0)
			return
		case <-tick.C:
			mod.PollPerfBuffer("events", 0)
		}
	}
}

func cstring(b []byte) string { return unix.ByteSliceToString(b) }
