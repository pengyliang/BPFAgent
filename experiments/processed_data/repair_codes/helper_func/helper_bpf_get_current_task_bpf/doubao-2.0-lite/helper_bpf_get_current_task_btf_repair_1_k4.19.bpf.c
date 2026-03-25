#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
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
int helper_absent(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&counter, &key);
    __u32 *target_tgid = bpf_map_lookup_elem(&cfg, &key);
    struct task_struct *task;
    __u32 cur_tgid;
    __u32 task_tgid;
    if (!val)
        return 0;
    cur_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (target_tgid && *target_tgid && cur_tgid != *target_tgid)
        return 0;
    /* Crutial block */
    task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;
    /* Crutial block end */
    
    bpf_probe_read(&task_tgid, sizeof(task_tgid), &task->tgid);
    if (task_tgid == 0 || task_tgid != cur_tgid)
        return 0;
    (*val)++;
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
