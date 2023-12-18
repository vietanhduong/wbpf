package wbpf

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

type RingBufCallback func(raw []byte)

type RingBufOptions struct {
	Callback RingBufCallback
	Async    bool
}

type RingBuf struct {
	table *Table
	*ringbuf.Reader
	callback RingBufCallback
}

func NewRingBuf(table *Table, opts *RingBufOptions) (*RingBuf, error) {
	if table.TableType() != ebpf.RingBuf {
		return nil, ErrIncorrectTableType
	}
	reader, err := ringbuf.NewReader(table.Map)
	if err != nil {
		return nil, fmt.Errorf("ringbuf new reader: %w", err)
	}

	if opts == nil {
		opts = &RingBufOptions{}
	}

	if opts.Callback == nil {
		opts.Callback = func(raw []byte) {}
	}

	this := &RingBuf{
		Reader: reader,
		table:  table,
	}

	if opts.Async {
		this.callback = func(raw []byte) { go opts.Callback(raw) }
	} else {
		this.callback = opts.Callback
	}
	return this, nil
}

func (rb *RingBuf) Poll(timeout time.Duration) (int, error) {
	if rb.Reader == nil {
		return -1, nil
	}
	var count int

	var t time.Time
	if timeout == 0 {
		t = time.Now().Add(-10 * time.Minute)
	} else if timeout > 0 {
		t = time.Now().Add(timeout)
	}
	rb.SetDeadline(t)

	var record ringbuf.Record
	for {
		if err := rb.ReadInto(&record); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ringbuf.ErrClosed) {
				return count, nil
			}
			return -1, fmt.Errorf("ringbuf read: %w", err)
		}
		rb.callback(record.RawSample)
		// reset cap and data. ref: https://github.com/cilium/ebpf/blob/14adc787359b2a2f948773ed286cfee2e7b3bffe/ringbuf/reader.go#L92
		record.RawSample = make([]byte, 0)
		count++
	}
}

func (rb *RingBuf) Close() error {
	if rb == nil || rb.Reader == nil {
		return nil
	}
	return rb.Reader.Close()
}
