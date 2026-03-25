typedef unsigned int __u32;
typedef unsigned long __u64;
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
struct trace_event_raw_sys_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int id;
    unsigned long args[6];
};
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
int btf_unsupported(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&counter, &key);
    __u32 *target_tgid = bpf_map_lookup_elem(&cfg, &key);
    __u32 tgid;
    long syscall_id;
    if (!val)
        return 0;
    tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (target_tgid && *target_tgid && tgid != *target_tgid)
        return 0;
    /* Crutial block */
    syscall_id = ctx->id;
    /* Crutial block end */
    if (syscall_id >= 0) {
        (*val)++;
    }
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
