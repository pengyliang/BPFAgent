#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
    __u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32); /* target tgid */
} cfg SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int dynptr_memory_model(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&counter, &key);
    __u32 *target_tgid = bpf_map_lookup_elem(&cfg, &key);
    struct bpf_dynptr ptr;
    struct event e = {};
    long ret;

    if (!val)
        return 0;

    if (target_tgid && *target_tgid) {
        __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        if (tgid != *target_tgid)
            return 0;
    }

    ret = bpf_ringbuf_reserve_dynptr(&rb, sizeof(e), 0, &ptr);
    if (ret) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);    // discard the reservation on failure to reserve memory
        return 0;
    }

    e.pid = bpf_get_current_pid_tgid() >> 32;
    ret = bpf_dynptr_write(&ptr, 0, &e, sizeof(e), 0);
    if (ret) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return 0;
    }
    bpf_ringbuf_submit_dynptr(&ptr, 0);

    (*val)++;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
