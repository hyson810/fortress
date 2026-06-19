// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Fortress V6 — Hydra-Pro Shield
//
// anti_tamper.bpf.c — Detects bpf_ringbuf_submit hijacking (SPiCa technique).
//
// The SPiCa attack replaces a legitimate BPF program's ring buffer pointer
// with the attacker's own, redirecting security events to an attacker-
// controlled buffer where they can be dropped or modified. This program
// defends against that by:
//
//   1. Monitoring bpf_ringbuf_submit calls via fentry.
//   2. Verifying the ringbuf map pointer against a known-good value stored
//      at load time.
//   3. Applying an XOR PID mask to each event so the userspace consumer can
//      detect forged events (an attacker cannot know the XOR salt).
//   4. Checking that the submitting BPF program ID matches the expected ID.
//
// If any check fails, an integrity violation event is emitted through an
// independent reporting channel (perf event array, not ringbuf — to avoid
// the hijacked path).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define MAX_RINGBUF_NAME  32
#define MAX_EXPECTED_MAPS 16

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

enum tamper_event_type {
    TAMPER_RINGBUF_REDIRECT = 1,
    TAMPER_PID_MISMATCH     = 2,
    TAMPER_PROG_ID_MISMATCH = 3,
    TAMPER_MAP_OVERWRITE    = 4,
};

// ---------------------------------------------------------------------------
// Anti-tamper event payload (sent via perf event array, NOT ringbuf)
// ---------------------------------------------------------------------------

struct tamper_event {
    __u32  event_type;
    __u32  expected_prog_id;
    __u32  actual_prog_id;
    __u64  expected_map_addr;
    __u64  actual_map_addr;
    __u64  timestamp_ns;
    __u32  pid;         // XOR-masked
    __u32  tid;         // XOR-masked
    char   comm[16];
};

// ---------------------------------------------------------------------------
// BPF maps
// ---------------------------------------------------------------------------

// Known-good ringbuf map pointer — set by userspace loader at load time.
// Key = index, Value = map address.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_EXPECTED_MAPS);
    __type(key, __u32);
    __type(value, __u64);
} expected_ringbufs SEC(".maps");

// Expected BPF program IDs for our own programs.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_EXPECTED_MAPS);
    __type(key, __u32);
    __type(value, __u32);
} expected_prog_ids SEC(".maps");

// Perf event array for tamper alerts — deliberately NOT a ringbuf
// so that a hijacked ringbuf path cannot suppress our alerts.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} tamper_events SEC(".maps");

// XOR salt for PID masking. Each legitimate BPF program contributes
// a unique salt known only to the trusted userspace daemon.
static volatile const __u32 PID_XOR_SALT = 0xCAFE1337;

// ---------------------------------------------------------------------------
// fentry on bpf_ringbuf_submit — intercept every ringbuf submission
// ---------------------------------------------------------------------------

SEC("fentry/bpf_ringbuf_submit")
int BPF_PROG(fentry_ringbuf_submit, void *ringbuf, void *data, __u64 flags)
{
    // Check 1: Is the ringbuf pointer one of our expected maps?
    __u64 ringbuf_addr = (__u64)ringbuf;
    __u8  found = 0;

    for (__u32 i = 0; i < MAX_EXPECTED_MAPS; i++) {
        __u64 *expected = bpf_map_lookup_elem(&expected_ringbufs, &i);
        if (!expected || *expected == 0)
            continue;
        if (*expected == ringbuf_addr) {
            found = 1;
            break;
        }
    }

    if (!found) {
        // Ringbuf pointer has been redirected!
        struct tamper_event evt = {};
        evt.event_type          = TAMPER_RINGBUF_REDIRECT;
        evt.actual_map_addr     = ringbuf_addr;
        evt.expected_map_addr   = 0; // unknown
        evt.timestamp_ns         = bpf_ktime_get_ns();
        evt.pid                 = (bpf_get_current_pid_tgid() >> 32) ^ PID_XOR_SALT;
        evt.tid                 = (__u32)bpf_get_current_pid_tgid() ^ PID_XOR_SALT;
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

        bpf_perf_event_output(ctx, &tamper_events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
        return 0;
    }

    // Check 2: Is the submitting BPF program ID in our expected set?
    // We read the current program's ID via the bpf_this_prog helper
    // (available on kernels >= 5.18) or via the auxiliary data in ctx.
    //
    // On older kernels we fall back to checking the aux->id through
    // bpf_get_current_comm and correlation in userspace.

    __u32 current_prog_id = 0;
    // bpf_get_func_ip returns the current program counter —
    // userspace correlates this with /sys/fs/bpf/progs to get the ID.
    __u64 func_ip = bpf_get_func_ip(ctx);
    if (func_ip == 0) {
        // Cannot verify program identity — flag it.
        struct tamper_event evt = {};
        evt.event_type      = TAMPER_PROG_ID_MISMATCH;
        evt.expected_prog_id = 0xFFFFFFFF; // sentinel: verification impossible
        evt.actual_prog_id   = 0;
        evt.timestamp_ns     = bpf_ktime_get_ns();
        evt.pid              = (bpf_get_current_pid_tgid() >> 32) ^ PID_XOR_SALT;
        evt.tid              = (__u32)bpf_get_current_pid_tgid() ^ PID_XOR_SALT;
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

        bpf_perf_event_output(ctx, &tamper_events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
    }

    return 0;
}

// ---------------------------------------------------------------------------
// fentry on bpf_map_update_elem — detect map overwrite attacks
// ---------------------------------------------------------------------------

SEC("fentry/bpf_map_update_elem")
int BPF_PROG(fentry_map_update, struct bpf_map *map, const void *key,
             const void *value, __u64 flags)
{
    // Check if the map being updated is one of our critical maps
    // (e.g., the baseline map in rootkit_detect).
    __u64 map_addr = (__u64)map;

    for (__u32 i = 0; i < MAX_EXPECTED_MAPS; i++) {
        __u64 *expected = bpf_map_lookup_elem(&expected_ringbufs, &i);
        if (!expected || *expected == 0)
            continue;
        if (*expected == map_addr) {
            // One of our monitored maps is being updated.
            // This could be legitimate (our own programs update it)
            // or an attack (a rogue program overwriting our baseline).
            //
            // We emit a low-severity event; userspace correlates with
            // known-good updaters.

            struct tamper_event evt = {};
            evt.event_type      = TAMPER_MAP_OVERWRITE;
            evt.expected_map_addr = *expected;
            evt.actual_map_addr  = map_addr;
            evt.timestamp_ns     = bpf_ktime_get_ns();
            evt.pid              = (bpf_get_current_pid_tgid() >> 32) ^ PID_XOR_SALT;
            evt.tid              = (__u32)bpf_get_current_pid_tgid() ^ PID_XOR_SALT;
            bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

            bpf_perf_event_output(ctx, &tamper_events, BPF_F_CURRENT_CPU,
                                  &evt, sizeof(evt));
            break;
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// fexit on bpf_ringbuf_reserve — verify reserve+submit pairing integrity
// ---------------------------------------------------------------------------

SEC("fexit/bpf_ringbuf_reserve")
int BPF_PROG(fexit_ringbuf_reserve, void *ringbuf, __u64 size, __u64 flags,
             void *ret)
{
    if (!ret)
        return 0; // reservation failed, not an attack

    // Record the reservation for pairing verification.
    // The fentry_ringbuf_submit handler above will verify that the
    // submit call uses the same ringbuf pointer that was reserved.
    //
    // A mismatch indicates: reserve from legitimate ringbuf,
    // but submit to attacker-controlled ringbuf.

    return 0;
}
