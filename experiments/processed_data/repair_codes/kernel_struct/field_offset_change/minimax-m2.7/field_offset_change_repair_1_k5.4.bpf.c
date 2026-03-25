#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef TASK_TGID_OFFSET
#define TASK_TGID_OFFSET 0x574
#endif

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

SEC("tracepoint/syscalls/sys_enter_openat")
int field_offset_change(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u32 tgid_from_offset = 0;
    __u32 current_tgid;
    __u64 *val = bpf_map_lookup_elem(&counter, &key);
    __u32 *target_tgid = bpf_map_lookup_elem(&cfg, &key);
    void *task;

    if (!val)
        return 0;

    if (target_tgid && *target_tgid) {
        __u32 cur = (__u32)(bpf_get_current_pid_tgid() >> 32);
        if (cur != *target_tgid)
            return 0;
    }

    task = (void *)bpf_get_current_task();
    if (!task)
        return 0;

    /* Crutial block */
    if (bpf_probe_read(&tgid_from_offset, sizeof(tgid_from_offset),
                       (const void *)((const char *)task + TASK_TGID_OFFSET)) != 0)
        return 0;
    /* Crutial block end */
    current_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (tgid_from_offset == current_tgid)   // cannot be deleted
        (*val)++;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
