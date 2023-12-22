// go:build ignore
#include "vmlinux.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#define LRU_CACHE_SIZE 128
#define ETH_P_IP 0x0800

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, LRU_CACHE_SIZE);
  __type(key, __u32);   // source IPv4 address
  __type(value, __u64); // packet count
} stats SEC(".maps");

static __always_inline int parse_src_ipv4(struct xdp_md *ctx, __u32 *ip_src) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) { // No eth header
    return 0;
  }

  // The protocol is not IPv4, so we can't parse an IPv4 source address.
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return 0;
  }

  // Then parse the IP header.
  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) {
    return 0;
  }

  // Return the source IP address in network byte order.
  *ip_src = (__u32)(ip->saddr);
  return 1;
}

SEC("xdp")
int xdp_stat_pkt(struct xdp_md *ctx) {
  __u32 ip_src;
  if (!parse_src_ipv4(ctx, &ip_src)) {
    goto done;
  }

  __u64 *pkt_count = bpf_map_lookup_elem(&stats, &ip_src);
  if (!pkt_count) {
    __u64 init_pkt_count = 1;
    bpf_map_update_elem(&stats, &ip_src, &init_pkt_count, BPF_ANY);
    goto done;
  }
  *pkt_count += 1;

done:
  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
