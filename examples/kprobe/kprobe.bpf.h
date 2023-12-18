// go:build ignore
#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#define RINGBUF_MAX_ENTRIES 16777216

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, RINGBUF_MAX_ENTRIES);
} pid_events SEC(".maps");

#define OP_PID_UNKNOWN 0
#define OP_PID_DEAD 1
#define OP_PID_EXEC 2

struct pid_event {
  __u32 op;
  __u32 pid;
};
struct pid_event pe__;

SEC("kprobe/disassociate_ctty")
int BPF_KPROBE(disassociate_ctty, int on_exit) {
  if (!on_exit) {
    return 0;
  }

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  if (pid == 0) {
    return 0;
  }
  struct pid_event event = {.op = OP_PID_DEAD, .pid = pid};

  bpf_ringbuf_output(&pid_events, &event, sizeof(event), 0);
  return 0;
}

SEC("kprobe/exec")
int BPF_KPROBE(exec, void *_) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  if (pid == 0) {
    return 0;
  }
  struct pid_event event = {.op = OP_PID_EXEC, .pid = pid};
  bpf_ringbuf_output(&pid_events, &event, sizeof(event), 0);
  return 0;
}

char __license[] SEC("license") = "Dual BSD/GPL";
