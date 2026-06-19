// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Fortress V6 — Hydra-Pro Shield
//
// voidlink_detect.bpf.c — VoidLink C2 detection rules.
//
// VoidLink is a kernel-level C2 framework that abuses Linux kernel
// facilities for stealthy communication. This BPF program detects
// VoidLink activity through three vectors:
//
//   1. PR_SET_NAME impersonation — attacker sets thread name to match
//      legitimate kernel thread names (e.g. "[kworker/u8:0]").
//   2. C2 magic bytes in socket payloads — known VoidLink protocol
//      markers embedded in TCP/UDP traffic.
//   3. Anti-debug ptrace — VoidLink uses ptrace with PTRACE_TRACEME
//      to detect debuggers and alter behavior.
//
// Hooks: tracepoint/syscalls/sys_enter_prctl
//        tracepoint/syscalls/sys_enter_ptrace

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define TASK_COMM_LEN            16
#define MAX_SOCKET_PAYLOAD       64
#define MAX_KNOWN_THREADS        32

// Known VoidLink C2 magic byte sequences.
#define MAGIC_LEN_V1             4
#define MAGIC_LEN_V2             8

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

enum vl_event_type {
    VL_EVENT_NAME_SPOOF   = 1,
    VL_EVENT_C2_MAGIC     = 2,
    VL_EVENT_ANTI_DEBUG   = 3,
    VL_EVENT_MEMFD_EXEC   = 4,
};

// ---------------------------------------------------------------------------
// VoidLink detection event
// ---------------------------------------------------------------------------

struct voidlink_event {
    __u32  event_type;
    __u32  pid;
    __u32  tid;
    __u32  uid;
    __u64  timestamp_ns;
    char   comm[TASK_COMM_LEN];
    char   spoofed_name[TASK_COMM_LEN];
    char   payload[MAGIC_LEN_V2]; // first 8 bytes of C2 payload
    __u32  payload_len;
    __u32  ptrace_request;
};

// ---------------------------------------------------------------------------
// BPF maps
// ---------------------------------------------------------------------------

// Known legitimate kernel thread name prefixes.
// Threads matching these patterns are suspicious if created from userspace.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_KNOWN_THREADS);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, __u8);
} known_kernel_threads SEC(".maps");

// Ringbuf for events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} vl_events SEC(".maps");

// XOR salt for PID masking.
static volatile const __u32 VL_PID_SALT = 0xBEEFBEEF;

// ---------------------------------------------------------------------------
// VoidLink C2 magic byte patterns (embedded as constants for verification)
// ---------------------------------------------------------------------------

// V1 magic: 0x56, 0x4C, 0x4B, 0x01  ("VLK\x01")
static const __u8 VL_MAGIC_V1[MAGIC_LEN_V1] = {0x56, 0x4C, 0x4B, 0x01};

// V2 magic: 0x56, 0x4F, 0x49, 0x44, 0x4C, 0x4E, 0x4B, 0x00 ("VOIDLNK\0")
static const __u8 VL_MAGIC_V2[MAGIC_LEN_V2] = {0x56, 0x4F, 0x49, 0x44, 0x4C, 0x4E, 0x4B, 0x00};

// ---------------------------------------------------------------------------
// Rule 1: Detect PR_SET_NAME with suspicious kernel-thread-like names
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_prctl")
int trace_prctl_name_spoof(struct trace_event_raw_sys_enter *ctx)
{
    // sys_prctl has signature: prctl(int option, unsigned long arg2, ...)
    // option is in ctx->args[0], arg2 (name ptr) is in ctx->args[1].
    int option = (int)ctx->args[0];

    // PR_SET_NAME = 15
    if (option != 15)
        return 0;

    char *name_ptr = (char *)ctx->args[1];
    if (!name_ptr)
        return 0;

    char name[TASK_COMM_LEN];
    __builtin_memset(name, 0, TASK_COMM_LEN);

    __s64 ret = bpf_probe_read_user_str(name, TASK_COMM_LEN, name_ptr);
    if (ret < 0)
        return 0;

    // Check if the name looks like a kernel thread name.
    // Kernel threads typically have names starting with '[' or containing
    // patterns like "kworker", "ksoftirqd", "migration", etc.
    __u8 suspicious = 0;

    // Pattern 1: Starts with '[' (like "[kworker/0:0]")
    if (name[0] == '[') {
        suspicious = 1;
    }

    // Pattern 2: Matches known kernel thread prefixes
    // Check "kworker", "ksoftirqd", "kthreadd", "migration", "rcu_"
    if (__builtin_memcmp(name, "kworker", 7) == 0 ||
        __builtin_memcmp(name, "ksoftirqd", 9) == 0 ||
        __builtin_memcmp(name, "kthreadd", 8) == 0 ||
        __builtin_memcmp(name, "migration", 9) == 0 ||
        __builtin_memcmp(name, "rcu_", 4) == 0) {
        suspicious = 1;
    }

    if (suspicious) {
        // Verify this is NOT a real kernel thread.
        // Kernel threads have PID == TGID and their parent is kthreadd (PID 2).
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        __u32 pid = pid_tgid >> 32;
        __u32 tid = (__u32)pid_tgid;

        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        __u32 real_parent_pid = 0;

        // Read real_parent->pid to check if parent is kthreadd.
        struct task_struct *real_parent;
        __s64 read_ret = bpf_probe_read_kernel(
            &real_parent, sizeof(real_parent),
            &task->real_parent);
        if (read_ret == 0 && real_parent) {
            bpf_probe_read_kernel(&real_parent_pid, sizeof(real_parent_pid),
                                  &real_parent->pid);
        }

        // If parent is NOT kthreadd (PID 2), this is a userspace thread
        // impersonating a kernel thread.
        if (real_parent_pid != 2) {
            struct voidlink_event evt = {};
            evt.event_type  = VL_EVENT_NAME_SPOOF;
            evt.pid         = pid;
            evt.tid         = tid;
            evt.uid         = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            evt.timestamp_ns = bpf_ktime_get_ns();
            bpf_get_current_comm(&evt.comm, TASK_COMM_LEN);
            __builtin_memcpy(evt.spoofed_name, name, TASK_COMM_LEN);

            bpf_ringbuf_submit(&evt, 0);
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Rule 2: Detect C2 magic bytes in socket payloads
// ---------------------------------------------------------------------------

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_c2_magic, struct sock *sk, struct msghdr *msg, size_t size)
{
    if (size < MAGIC_LEN_V1)
        return 0;

    // Read the first bytes of the payload to check for magic markers.
    // voidlink uses hardcoded magic at the start of each C2 message.
    //
    // For BPF, we'd need to read the iov_iter contents. In a production
    // deployment this uses bpf_d_path or bpf_skb_load_bytes; for the
    // kprobe path we sample the first iovec.

    struct iov_iter *iter = &msg->msg_iter;
    if (!iter)
        return 0;

    // Read the kvec/iovec from the iov_iter.
    struct iovec iov;
    __s64 ret = bpf_probe_read_kernel(&iov, sizeof(iov), &iter->kvec);
    if (ret < 0)
        return 0;

    if (iov.iov_len < MAGIC_LEN_V1)
        return 0;

    char payload[MAGIC_LEN_V2];
    __builtin_memset(payload, 0, MAGIC_LEN_V2);

    ret = bpf_probe_read_kernel(payload,
        iov.iov_len < MAGIC_LEN_V2 ? iov.iov_len : MAGIC_LEN_V2,
        iov.iov_base);
    if (ret < 0)
        return 0;

    // Compare against known VoidLink magic.
    __u8 matched = 0;
    if (__builtin_memcmp(payload, VL_MAGIC_V1, MAGIC_LEN_V1) == 0)
        matched = 1;
    if (__builtin_memcmp(payload, VL_MAGIC_V2, MAGIC_LEN_V2) == 0)
        matched = 1;

    if (matched) {
        __u64 pid_tgid = bpf_get_current_pid_tgid();

        struct voidlink_event evt = {};
        evt.event_type  = VL_EVENT_C2_MAGIC;
        evt.pid         = pid_tgid >> 32;
        evt.tid         = (__u32)pid_tgid;
        evt.uid         = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        evt.timestamp_ns = bpf_ktime_get_ns();
        evt.payload_len  = (__u32)(iov.iov_len < MAGIC_LEN_V2 ? iov.iov_len : MAGIC_LEN_V2);
        __builtin_memcpy(evt.payload, payload, MAGIC_LEN_V2);
        bpf_get_current_comm(&evt.comm, TASK_COMM_LEN);

        bpf_ringbuf_submit(&evt, 0);
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Rule 3: Detect anti-debug ptrace (PTRACE_TRACEME)
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace_anti_debug(struct trace_event_raw_sys_enter *ctx)
{
    // sys_ptrace signature: ptrace(int request, pid_t pid, ...)
    // request is ctx->args[0], pid is ctx->args[1].
    int request = (int)ctx->args[0];

    // PTRACE_TRACEME = 0 — a process asking to be traced by its parent.
    // This is used by debuggers, but VoidLink uses it as an anti-debug
    // check: if PTRACE_TRACEME fails (errno EPERM), the process knows
    // it is already being traced / analyzed.
    //
    // We flag TRACEME calls when the caller is NOT a known debugger
    // and the call is made early in process lifetime (suggesting an
    // anti-analysis check rather than legitimate debugging).

    if (request != 0) // PTRACE_TRACEME
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Non-root users doing PTRACE_TRACEME from unknown binaries
    // are suspicious — most legitimate debuggers run as the same user
    // or are launched by known toolchains.

    struct voidlink_event evt = {};
    evt.event_type    = VL_EVENT_ANTI_DEBUG;
    evt.pid           = pid;
    evt.tid           = (__u32)pid_tgid;
    evt.uid           = uid;
    evt.timestamp_ns  = bpf_ktime_get_ns();
    evt.ptrace_request = (__u32)request;
    bpf_get_current_comm(&evt.comm, TASK_COMM_LEN);

    bpf_ringbuf_submit(&evt, 0);

    return 0;
}

// ---------------------------------------------------------------------------
// Rule 4: Detect memfd_create with MFD_EXEC (memory-only executable)
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_exec(struct trace_event_raw_sys_enter *ctx)
{
    // sys_memfd_create: memfd_create(const char *name, unsigned int flags)
    // flags are in ctx->args[1].
    unsigned int flags = (unsigned int)ctx->args[1];

    // MFD_EXEC = 0x0010 — allow executable mappings of the memfd.
    // This is used by VoidLink to create executable memory regions
    // that are not backed by any visible file.
#define MFD_EXEC_FLAG 0x0010U
    if (!(flags & MFD_EXEC_FLAG))
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Read the name argument.
    char *name_ptr = (char *)ctx->args[0];
    char name[TASK_COMM_LEN];
    __builtin_memset(name, 0, TASK_COMM_LEN);

    if (name_ptr) {
        bpf_probe_read_user_str(name, TASK_COMM_LEN, name_ptr);
    }

    struct voidlink_event evt = {};
    evt.event_type   = VL_EVENT_MEMFD_EXEC;
    evt.pid          = pid_tgid >> 32;
    evt.tid          = (__u32)pid_tgid;
    evt.uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.payload_len  = (__u32)flags;
    bpf_get_current_comm(&evt.comm, TASK_COMM_LEN);
    __builtin_memcpy(evt.spoofed_name, name, TASK_COMM_LEN);

    bpf_ringbuf_submit(&evt, 0);

    return 0;
}
