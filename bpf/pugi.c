//go:build ignore

// SPDX-License-Identifier: GPL-2.0
//
// pugi — eBPF-based HTTP traffic observer
//
// Hooks into syscall tracepoints to capture read/write data from a target
// process (by PID). Captured data is sent to userspace via a perf event
// buffer where HTTP parsing and filtering happens.
//
// Compatible with Linux 4.18+ (RHEL 8 / Rocky 8 / CentOS Stream 8):
//   - Uses perf event array (not ringbuf, which requires 5.8+)
//   - Uses bpf_probe_read (not bpf_probe_read_user, which requires 5.5+)
//   - No CO-RE / BTF dependency — works on kernels without
//     CONFIG_DEBUG_INFO_BTF
//
// Hooked syscalls:
//   INBOUND : read, recvfrom
//   OUTBOUND: write, sendto

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "GPL";

// ============================================================================
// Constants
// ============================================================================
#define MAX_DATA_SIZE   8192
#define TASK_COMM_LEN   16
#define PERF_PAGES      4096   // 4096 pages × 4 KB = 16 MB

#define DIR_INBOUND  0
#define DIR_OUTBOUND 1

// ============================================================================
// Stable tracepoint context definitions
//
// The syscall tracepoint format is stable kernel ABI.
// These structs are defined manually so the program compiles and runs
// without kernel-headers or BTF on the target system.
// ============================================================================

// sys_enter_* tracepoint context: id + 6 args
struct sys_enter_ctx {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           id;          // syscall number
    unsigned long  args[6];     // syscall arguments
};

// sys_exit_* tracepoint context: id + return value
struct sys_exit_ctx {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           id;          // syscall number
    long           ret;         // return value
};

// ============================================================================
// Data structures
// ============================================================================

// Per-event payload sent to userspace
struct event {
    __u32 pid;
    __u32 tid;
    __u32 fd;
    __u32 direction;      // DIR_INBOUND or DIR_OUTBOUND
    __u32 data_len;
    __u32 flags;
    __u64 timestamp_ns;
    __u8  data[MAX_DATA_SIZE];
    char comm[TASK_COMM_LEN];
};

// Per-thread saved syscall arguments (enter -> exit handoff)
//
// BPF does NOT allow saving the tracepoint ctx pointer across enter/exit
// (it lives on the kernel stack and is invalidated). Instead we save the
// raw argument values here and re-read them on the exit probe.
struct args_save {
    unsigned long buf_ptr;
    unsigned long fd;
    unsigned long count;
    __u32 flags;};

// ============================================================================
// Maps
// ============================================================================

// Perf event array — pushes captured data to userspace.
// Compatible with all kernels since 4.4 (ringbuf requires 5.8+).
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} events SEC(".maps");

// Per-CPU scratch buffer for building events.
// 'struct event' (~8 KB) exceeds BPF's 512-byte stack limit, so we
// assemble it in a per-CPU map slot and then submit via perf.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} temp_event SEC(".maps");

// Target PID (key=0, value=pid). 0 = disabled.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid SEC(".maps");

// Active syscall args, keyed by tid
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct args_save);
} active_args SEC(".maps");

// ============================================================================
// Helpers
// ============================================================================

// Check whether the current task matches the configured target PID.
static __always_inline int is_target(void) {
    __u32 key = 0;
    __u32 *pid = bpf_map_lookup_elem(&target_pid, &key);
    if (!pid || *pid == 0)
        return 0;
    return (bpf_get_current_pid_tgid() >> 32) == *pid;
}

// Save syscall enter arguments for the current thread.
static __always_inline void save_args(__u32 tid, unsigned long buf_ptr,
                                       unsigned long fd, unsigned long count,
                                       __u32 flags) {
    struct args_save a = {
        .buf_ptr = buf_ptr,
        .fd      = fd,
        .count   = count,
        .flags   = flags,
    };
    bpf_map_update_elem(&active_args, &tid, &a, BPF_ANY);
}

// Read captured data from userspace and push it via perf event output.
//
// ctx   — the tracepoint context pointer (required by bpf_perf_event_output)
// tid   — thread id (map key for active_args)
// ret   — syscall return value (bytes read/written, or error)
// direction — DIR_INBOUND or DIR_OUTBOUND
static __always_inline void emit_event(void *ctx, __u32 tid, __s64 ret,
                                        __u32 direction) {
    if (ret <= 0)
        goto cleanup;

    struct args_save *a = bpf_map_lookup_elem(&active_args, &tid);
    if (!a)
        goto cleanup;

    __u32 data_len = ret > MAX_DATA_SIZE ? MAX_DATA_SIZE : (__u32)ret;

    // Use per-CPU scratch buffer — stack is limited to 512 bytes
    __u32 zero = 0;
    struct event *e = bpf_map_lookup_elem(&temp_event, &zero);
    if (!e)
        goto cleanup;

    // Fill event metadata
    __u64 tgid_pid = bpf_get_current_pid_tgid();
    e->pid          = tgid_pid >> 32;
    e->tid          = (__u32)tgid_pid;
    e->fd           = (__u32)a->fd;
    e->direction    = direction;
    e->data_len     = data_len;
    e->flags        = a->flags;
    e->timestamp_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // bpf_probe_read is available on all kernels since 4.4.
    // (bpf_probe_read_user was added in 5.5 and is not used here.)
    bpf_probe_read(&e->data, data_len, (void *)a->buf_ptr);

    // Submit via perf event output
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));

cleanup:
    bpf_map_delete_elem(&active_args, &tid);
}

// ============================================================================
// sys_enter probes — save arguments
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_read")
int tp_enter_read(struct sys_enter_ctx *ctx) {
    if (!is_target()) return 0;
    __u32 tid = bpf_get_current_pid_tgid();
    save_args(tid,
              ctx->args[1],   // buf
              ctx->args[0],   // fd
              ctx->args[2],   // count
              0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tp_enter_write(struct sys_enter_ctx *ctx) {
    if (!is_target()) return 0;
    __u32 tid = bpf_get_current_pid_tgid();
    save_args(tid,
              ctx->args[1],   // buf
              ctx->args[0],   // fd
              ctx->args[2],   // count
              0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tp_enter_recvfrom(struct sys_enter_ctx *ctx) {
    if (!is_target()) return 0;
    __u32 tid = bpf_get_current_pid_tgid();
    save_args(tid,
              ctx->args[1],       // buf
              ctx->args[0],       // fd
              ctx->args[2],       // len
              (__u32)ctx->args[4]); // flags
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tp_enter_sendto(struct sys_enter_ctx *ctx) {
    if (!is_target()) return 0;
    __u32 tid = bpf_get_current_pid_tgid();
    save_args(tid,
              ctx->args[1],       // buf
              ctx->args[0],       // fd
              ctx->args[2],       // len
              (__u32)ctx->args[4]); // flags
    return 0;
}

// ============================================================================
// sys_exit probes — read buffer, emit event via perf
// ============================================================================

SEC("tracepoint/syscalls/sys_exit_read")
int tp_exit_read(struct sys_exit_ctx *ctx) {
    if (!is_target()) return 0;
    emit_event(ctx, bpf_get_current_pid_tgid(), ctx->ret, DIR_INBOUND);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int tp_exit_write(struct sys_exit_ctx *ctx) {
    if (!is_target()) return 0;
    emit_event(ctx, bpf_get_current_pid_tgid(), ctx->ret, DIR_OUTBOUND);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int tp_exit_recvfrom(struct sys_exit_ctx *ctx) {
    if (!is_target()) return 0;
    emit_event(ctx, bpf_get_current_pid_tgid(), ctx->ret, DIR_INBOUND);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int tp_exit_sendto(struct sys_exit_ctx *ctx) {
    if (!is_target()) return 0;
    emit_event(ctx, bpf_get_current_pid_tgid(), ctx->ret, DIR_OUTBOUND);
    return 0;
}
