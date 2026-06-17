// SPDX-License-Identifier: GPL-2.0
/*
 * Fortress v6 — XDP Ingress Packet Filter
 *
 * Runs at the NIC driver level (~50ns overhead per packet).
 * Drops or passes packets based on BPF map lookups:
 *   - whitelist:     LPM trie for CIDR-based allow rules (overrides blocklist)
 *   - blocked_ips:   hash set of blocked IPv4 addresses (LRU, max 10000)
 *   - rate_limit:    per-IP token bucket (LRU hash, value = remaining tokens)
 *   - stats:         per-CPU counters for passed / dropped / rate_limited
 *
 * Requires Linux kernel 5.4+.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ------------------------------------------------------------------ */
/* Map definitions                                                    */
/* ------------------------------------------------------------------ */

/*
 * Whitelist — LPM trie with CIDR prefix match.
 * Key:   __u32 IPv4 address (network byte order).
 * Value: __u8  (non-zero = allowed).
 * Entries managed by userspace via `bpftool map` or libbpf.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key,  __u32);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist SEC(".maps");

/* Blocked IPv4 addresses.  Value is 1 if blocked; key is the raw u32. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key,  __u32);
    __type(value, __u8);
} blocked_ips SEC(".maps");

/*
 * Per-IP token bucket for rate limiting.
 * Key: IPv4 source address (u32, network byte order).
 * Value: current token count (u32).  Refilled by userspace periodically.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 50000);
    __type(key,  __u32);
    __type(value, __u32);
} rate_limit SEC(".maps");

/*
 * Per-CPU statistics counters.
 * Index 0: passed
 * Index 1: dropped (blocked IP)
 * Index 2: rate_limited
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key,  __u32);
    __type(value, __u64);
} stats SEC(".maps");

/* ------------------------------------------------------------------ */
/* XDP program                                                        */
/* ------------------------------------------------------------------ */

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(unsigned long)ctx->data_end;
    void *data     = (void *)(unsigned long)ctx->data;

    /* --- 1. Parse Ethernet header ---------------------------------- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    /* Only IPv4 is handled. */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* --- 2. Parse IP header ---------------------------------------- */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    __u32 src_ip = ip->saddr;

    /* --- 3. Check whitelist (CIDR match via LPM trie) -------------- */
    __u8 *allowed = bpf_map_lookup_elem(&whitelist, &src_ip);
    if (allowed && *allowed) {
        __u32 key_pass = 0;
        __u64 *cnt = bpf_map_lookup_elem(&stats, &key_pass);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);
        return XDP_PASS;
    }

    /* --- 4. Check blocked_ips map ---------------------------------- */
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (blocked && *blocked) {
        /* Increment drop counter */
        __u32 key_drop = 1;
        __u64 *cnt = bpf_map_lookup_elem(&stats, &key_drop);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);
        return XDP_DROP;
    }

    /* --- 5. Check rate_limit map (token bucket) -------------------- */
    __u32 *tokens = bpf_map_lookup_elem(&rate_limit, &src_ip);
    if (tokens && *tokens < 1) {
        /* No tokens left — rate-limit the packet */
        __u32 key_rl = 2;
        __u64 *cnt = bpf_map_lookup_elem(&stats, &key_rl);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);
        return XDP_DROP;
    }

    /* Decrement token count (best-effort; atomic not needed per-CPU
       in typical setups, but __sync is safe regardless). */
    if (tokens)
        __sync_fetch_and_add(tokens, -1);

    /* --- 6. Increment pass counter --------------------------------- */
    __u32 key_pass = 0;
    __u64 *cnt = bpf_map_lookup_elem(&stats, &key_pass);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
