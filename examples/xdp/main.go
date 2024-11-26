package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vietanhduong/wbpf"
	"github.com/vietanhduong/wbpf/pkg/logging"
)

//go:embed xdp.bpf.o
var elfcontent []byte

var log = logging.DefaultLogger.WithFields(logrus.Fields{"example": "xdp"})

func main() {
	if len(elfcontent) == 0 {
		log.Error("No elf content, you might need to run `make build-xdp` first.")
		os.Exit(1)
	}

	var ifname string
	var loglevel string
	flag.StringVar(&ifname, "interface", "", "Interface name which you want to attach.")
	flag.StringVar(&loglevel, "log-level", "info", "Log level.")
	flag.Parse()

	logging.SetupLogging(logging.WithLogLevel(loglevel))
	if ifname == "" {
		log.Errorf("Interface name is required")
		os.Exit(1)
	}

	mod, _, err := wbpf.NewModule(wbpf.WithElfFileContent(elfcontent))
	if err != nil {
		log.Errorf("Failed to new wbpf module: %v", err)
		os.Exit(1)
	}
	defer mod.Close()

	tbl, err := mod.GetTable("stats")
	if err != nil {
		log.Errorf("Failed to get table stats: %v", err)
		os.Exit(1)
	}

	if _, err = mod.AttachXDP(ifname, "xdp_stat_pkt", 0); err != nil {
		log.Errorf("Failed to attach XDP to interface %s: %v", ifname, err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	ticker := time.NewTicker(time.Second)
	ob := &observer{tbl}
	for {
		select {
		case <-ctx.Done():
			if err = ob.poll(); err != nil {
				log.Errorf("Failed to poll: %v", err)
			}
			return
		case <-ticker.C:
			if err = ob.poll(); err != nil {
				log.Errorf("Failed to poll: %v", err)
			}
		}
	}
}

type observer struct {
	tbl *wbpf.Table
}

func (o *observer) poll() error {
	var (
		sb  strings.Builder
		key netip.Addr
		val uint64
	)
	iter := o.tbl.Iterate()
	for iter.Next(&key, &val) {
		sourceIP := key // IPv4 source address in network byte order.
		packetCount := val
		sb.WriteString(fmt.Sprintf("\t%s => %d\n", sourceIP, packetCount))
	}
	if err := iter.Err(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Stats:\n%s", sb.String())
	return nil
}
