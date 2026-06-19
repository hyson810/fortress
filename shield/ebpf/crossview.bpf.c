// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Fortress V6 — Hydra-Pro Shield
//
// crossview.bpf.c — NMI hardware heartbeat vs software telemetry cross-validation.
//
// This BPF program attaches to the NMI (non-maskable interrupt) as a perf
// event and counts hardware interrupt occurrences independently of any
// software-level telemetry. By comparing the hardware NMI count against
// software event counters (BPF program run counts, tracepoint hits), we
// detect eBPF program tampering.
//
// Attack defended: If an attacker hooks or replaces a BPF program (e.g.
// via SPiCa or bpf_ringbuf_submit hijacking), the software counters will
// diverge from the hardware NMI count because the attacker's modified
// program will skip or alter event reporting. The NMI counter cannot be
// intercepted because NMIs are non-maskable — they fire regardless of
// interrupt flags.
//
// Output is pushed to a BPF perf event array for low-latency userspace
// consumption.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Maximum divergence allowed between hardware and software counters
// before triggering an alert (expressed as a ratio * 100).
#define MAX_DIVERGENCE_PCT   10

// Number of CPU cores to track individually.
#define MAX_CPUS            128

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

enum xv_event_type {
    XV_EVENT_NMI_COUNT     = 1,
    XV_EVENT_DIVERGENCE    = 2,
    XV_EVENT_TAMPER         = 3,
};

// ---------------------------------------------------------------------------
// Cross-view event payload
// ---------------------------------------------------------------------------

struct crossview_event {
    __u32  cpu;
    __u32  event_type;
    __u64  hw_nmi_count;
    __u64  sw_bpf_count;
    __u64  sw_tp_count;
    __u64  timestamp_ns;
    __u64  divergence_pct;
    __u32  pid;
};

// ---------------------------------------------------------------------------
// BPF maps
// ---------------------------------------------------------------------------

// Per-CPU hardware NMI counter.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} hw_nmi_counter SEC(".maps");

// Per-CPU software BPF program execution counter.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sw_bpf_counter SEC(".maps");

// Per-CPU tracepoint hit counter (software side).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sw_tp_counter SEC(".maps");

// Perf event array for output to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} xv_events SEC(".maps");

// ---------------------------------------------------------------------------
// NMI handler: counts hardware interrupts
// ---------------------------------------------------------------------------

SEC("perf_event")
int nmi_handler(struct bpf_perf_event_data *ctx)
{
    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&hw_nmi_counter, &key);
    if (!counter)
        return 0;

    // Atomically increment the NMI counter.
    // Per-CPU maps are safe from preemption on the same CPU.
    __sync_fetch_and_add(counter, 1);

    return 0;
}

// ---------------------------------------------------------------------------
// Software-side: tracepoint hit counter
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_getpid")
int tp_sw_counter(void *ctx)
{
    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&sw_tp_counter, &key);
    if (!counter)
        return 0;

    __sync_fetch_and_add(counter, 1);
    return 0;
}

// ---------------------------------------------------------------------------
// Periodic cross-validation check
// ---------------------------------------------------------------------------

SEC("syscall")
int crossview_check(void *ctx)
{
    __u32 key = 0;
    __u64 *hw_val = bpf_map_lookup_elem(&hw_nmi_counter, &key);
    __u64 *sw_bpf = bpf_map_lookup_elem(&sw_bpf_counter, &key);
    __u64 *sw_tp  = bpf_map_lookup_elem(&sw_tp_counter, &key);

    if (!hw_val || !sw_bpf || !sw_tp)
        return 0;

    __u64 hw = *hw_val;
    __u64 sw = *sw_bpf + *sw_tp;

    // If the hardware counter significantly exceeds the software counter,
    // someone may be suppressing software events.
    __u64 divergence = 0;
    if (hw > sw) {
        divergence = ((hw - sw) * 100) / (hw ? hw : 1);
    }

    struct crossview_event evt = {};
    evt.cpu             = bpf_get_smp_processor_id();
    evt.event_type      = XV_EVENT_DIVERGENCE;
    evt.hw_nmi_count    = hw;
    evt.sw_bpf_count    = *sw_bpf;
    evt.sw_tp_count     = *sw_tp;
    evt.timestamp_ns    = bpf_ktime_get_ns();
    evt.divergence_pct  = divergence;
    evt.pid             = (__u32)(bpf_get_current_pid_tgid() >> 32);

    if (divergence > MAX_DIVERGENCE_PCT) {
        evt.event_type = XV_EVENT_TAMPER;
    }

    bpf_perf_event_output(ctx, &xv_events, BPF_F_CURRENT_CPU,
                          &evt, sizeof(evt));

    return 0;
}

// ---------------------------------------------------------------------------
// BPF program execution counter — called from other BPF programs
// via tail call to track software-side execution fidelity.
// ---------------------------------------------------------------------------

SEC("raw_tracepoint/bpf_trace_printk")
int bpf_exec_counter(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&sw_bpf_counter, &key);
    if (!counter)
        return 0;

    __sync_fetch_and_add(counter, 1);
    return 0;
}
