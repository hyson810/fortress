// SPDX-License-Identifier: GPL-2.0
/*
 * Fortress v6 — TC Egress Packet Monitor
 *
 * Attached as a Traffic Control (TC) egress filter.  Monitors outbound
 * traffic for data exfiltration detection without blocking legitimate
 * flows (always returns TC_ACT_OK).
 *
 * Maps:
 *   - egress_stats: per-CPU counters (bytes + packets) keyed by dest IP
 *   - egress_alerts: perf event array for alerting userspace when a
 *     single destination exceeds 1 MB within a 60-second window.
 *
 * Requires Linux kernel 5.4+.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>

/* ------------------------------------------------------------------ */
/* Data structures                                                    */
/* ------------------------------------------------------------------ */

/* Per-destination counter value stored in egress_stats map. */
struct egress_entry {
    __u64 bytes;
    __u64 packets;
    /* Monotonic timestamp (ns) of the first packet in the current window. */
    __u64 window_start;
};

/* Alert payload sent to userspace via the perf event array. */
struct egress_alert {
    __u32 dest_ip;      /* Destination IPv4 address (network byte order). */
    __u64 byte_count;   /* Total bytes sent in the current window. */
    __u64 timestamp;    /* Kernel monotonic timestamp (ns) when threshold hit. */
};

/* ------------------------------------------------------------------ */
/* Constants                                                          */
/* ------------------------------------------------------------------ */

/* 1 MiB threshold */
#define EGRESS_THRESHOLD_BYTES ((__u64)(1ULL << 20))
/* 60-second window in nanoseconds */
#define EGRESS_WINDOW_NS     ((__u64)(60ULL * 1000000000ULL))

/* ------------------------------------------------------------------ */
/* Map definitions                                                    */
/* ------------------------------------------------------------------ */

/*
 * Per-CPU byte/packet counters keyed by destination IP.
 * LRU eviction keeps memory bounded when many destinations are seen.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key,  __u32);
    __type(value, struct egress_entry);
} egress_stats SEC(".maps");

/*
 * Perf event array for pushing alerts to userspace.
 * Must be sized to a power of two.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 64);
    __type(key,  __u32);
    __type(value, __u32);
} egress_alerts SEC(".maps");

/* ------------------------------------------------------------------ */
/* TC egress program                                                  */
/* ------------------------------------------------------------------ */

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    /* --- 1. Parse Ethernet header ---------------------------------- */
    void *data_end = (void *)(unsigned long)skb->data_end;
    void *data     = (void *)(unsigned long)skb->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* --- 2. Parse IP header ---------------------------------------- */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u32 dest_ip = ip->daddr;
    __u64 now     = bpf_ktime_get_ns();
    __u64 pkt_len = skb->len;

    /* --- 3. Update per-destination counters ------------------------ */
    struct egress_entry *entry = bpf_map_lookup_elem(&egress_stats, &dest_ip);
    if (!entry) {
        /* First packet to this destination — seed a new entry. */
        struct egress_entry seed = {
            .bytes        = pkt_len,
            .packets      = 1,
            .window_start = now,
        };
        bpf_map_update_elem(&egress_stats, &dest_ip, &seed, BPF_ANY);
        return TC_ACT_OK;
    }

    /* Reset window if it has expired (60 s). */
    if (now - entry->window_start > EGRESS_WINDOW_NS) {
        entry->bytes        = pkt_len;
        entry->packets      = 1;
        entry->window_start = now;
        return TC_ACT_OK;
    }

    /* Accumulate counters. */
    entry->bytes   += pkt_len;
    entry->packets += 1;

    /* --- 4. Threshold check ---------------------------------------- */
    if (entry->bytes >= EGRESS_THRESHOLD_BYTES) {
        struct egress_alert alert = {
            .dest_ip    = dest_ip,
            .byte_count = entry->bytes,
            .timestamp  = now,
        };
        bpf_perf_event_output(skb, &egress_alerts, BPF_F_CURRENT_CPU,
                              &alert, sizeof(alert));

        /* Reset window after alert to avoid alert storms. */
        entry->bytes        = 0;
        entry->packets      = 0;
        entry->window_start = now;
    }

    /* Always pass through — this is a monitor, not a filter. */
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
