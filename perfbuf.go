package wbpf

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

const DEFAULT_PERF_BUF_SIZE = 1024 * 1024

type (
	PerfBufRawCallback  func(raw []byte)
	PerfBufLostCallback func(lost uint64)
)

type PerfBufOptions struct {
	RawCallback   PerfBufRawCallback
	LostCallback  PerfBufLostCallback
	Async         bool
	PerCPUBufSize int
}

type PerfBuf struct {
	table *Table
	*perf.Reader
	rawcb  PerfBufRawCallback
	lostcb PerfBufLostCallback
}

func NewPerfBuffer(table *Table, opts *PerfBufOptions) (*PerfBuf, error) {
	if table.TableType() != ebpf.PerfEventArray {
		return nil, ErrIncorrectTableType
	}

	if opts == nil {
		opts = &PerfBufOptions{}
	}

	bufsize := opts.PerCPUBufSize
	if bufsize <= 0 {
		bufsize = DEFAULT_PERF_BUF_SIZE
	}

	reader, err := perf.NewReader(table.Map, bufsize)
	if err != nil {
		return nil, fmt.Errorf("perf new reader: %w", err)
	}

	this := &PerfBuf{
		Reader: reader,
		table:  table,
	}

	if opts.Async {
		if opts.RawCallback != nil {
			this.rawcb = func(raw []byte) { go opts.RawCallback(raw) }
		}
		if opts.LostCallback != nil {
			this.lostcb = func(lost uint64) { go opts.LostCallback(lost) }
		}
	} else {
		this.rawcb = opts.RawCallback
		this.lostcb = opts.LostCallback
	}
	return this, nil
}

func (pb *PerfBuf) Poll(timeout time.Duration) (int, error) {
	if pb.Reader == nil {
		return -1, nil
	}
	var count int

	var t time.Time
	if timeout == 0 {
		t = time.Now().Add(-10 * time.Minute)
	} else if timeout > 0 {
		t = time.Now().Add(timeout)
	}
	pb.SetDeadline(t)

	var record perf.Record
	for {
		if err := pb.ReadInto(&record); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, perf.ErrClosed) {
				return count, nil
			}
			return -1, fmt.Errorf("ringbuf read: %w", err)
		}
		if pb.rawcb != nil {
			pb.rawcb(record.RawSample)
		}
		if pb.lostcb != nil && record.LostSamples > 0 {
			pb.lostcb(record.LostSamples)
		}
		// reset cap and data
		record.RawSample = make([]byte, 0)
		count++
	}
}

func (rb *PerfBuf) Close() error {
	if rb == nil || rb.Reader == nil {
		return nil
	}
	return rb.Reader.Close()
}
