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
    int i;
    
    /* Extended offsets for task_struct->tgid in different kernel versions */
    __u64 possible_offsets[] = {
        0x570, 0x574, 0x578, 0x580, 0x588, 0x590, 0x598,
        0x5a0, 0x5a8, 0x5b0, 0x5b8, 0x5c0, 0x5c8, 0x5d0,
        0x5d8, 0x5e0, 0x5e8, 0x5f0, 0x5f8
    };
    int num_offsets = sizeof(possible_offsets) / sizeof(possible_offsets[0]);
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
    current_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    
    /* Try multiple possible offsets */
    for (i = 0; i < num_offsets; i++) {
        if (bpf_probe_read_kernel(&tgid_from_offset, sizeof(tgid_from_offset),
                                  (const void *)((const char *)task + possible_offsets[i])) == 0) {
            if (tgid_from_offset == current_tgid) {
                (*val)++;
                break;
            }
        }
    }
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
