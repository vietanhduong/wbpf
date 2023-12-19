#include "vmlinux.h"
#include "bpf_helpers.h"

#define TOTAL_ENTRIES 65536
#define MAX_STACK_DEPTH 127
#define RINGBUF_MAX_ENTRIES 16777216

#define KERNEL_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

struct stack_t {
  __u32 pid;
  __s64 user_stack;
  __s64 kernel_stack;
};

struct {
  __uint(type, BPF_MAP_TYPE_STACK_TRACE);
  __uint(key_size, sizeof(u32));
  __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
  __uint(max_entries, TOTAL_ENTRIES);
} stack_traces SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, RINGBUF_MAX_ENTRIES);
} histogram SEC(".maps");

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t pid = id;

  struct stack_t key = {};
  key.pid = tgid;
  key.kernel_stack = bpf_get_stackid(ctx, &stack_traces, KERNEL_STACKID_FLAGS);
  key.user_stack = bpf_get_stackid(ctx, &stack_traces, USER_STACKID_FLAGS);
  bpf_ringbuf_output(&histogram, &key, sizeof(key), 0);
  return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
