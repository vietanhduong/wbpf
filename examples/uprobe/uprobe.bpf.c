// go:build ignore
#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#define OFFSET(ptr, offset) (void *)ptr + offset * 8
#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct event_t {
  __u8 method[16];
  __u8 host[256];
  __u8 path[256];
  __u8 query[512];
};

// Because BPF progams are limited in 512 bytes stack. We store this value per
// CPU and use it as a heap allocated value.
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct event_t);
  __uint(max_entries, 1);
} event_entry SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("uprobe/main.handler")
int BPF_UPROBE(main_handler) {
  int zero = 0;
  struct event_t *e = bpf_map_lookup_elem(&event_entry, &zero);
  if (e == NULL) {
    return 0;
  }

  // Because we have already examined the main.handler using GDB and know
  // exactly which register contains the http.Request ($rcx). Therefore, in this
  // example, I simply read the register directly.
  void *req = (void *)PT_REGS_PARM4(ctx);
  __u64 data;
  __u64 len;

  // method data start at offset 0
  bpf_probe_read(&data, sizeof(data), OFFSET(req, 0));
  bpf_probe_read(&len, sizeof(len), OFFSET(req, 1));
  bpf_probe_read(&e->method, MIN(len, sizeof(e->method)), (void *)data);

  // url data start at offset 16
  __u64 url;
  bpf_probe_read(&url, sizeof(url), OFFSET(req, 2));

  // path start at offset 56
  bpf_probe_read(&data, sizeof(data), OFFSET(url, 7));
  bpf_probe_read(&len, sizeof(len), OFFSET(url, 8));
  bpf_probe_read(&e->path, MIN(len, sizeof(e->path)), (void *)data);

  // query start at offset 96
  bpf_probe_read(&data, sizeof(data), OFFSET(url, 12));
  bpf_probe_read(&len, sizeof(len), OFFSET(url, 13));
  bpf_probe_read(&e->query, MIN(len, sizeof(e->query)), (void *)data);

  // host start at offset 128
  bpf_probe_read(&data, sizeof(data), OFFSET(req, 16));
  bpf_probe_read(&len, sizeof(len), OFFSET(req, 17));
  bpf_probe_read(&e->host, MIN(len, sizeof(e->host)), (void *)data);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
