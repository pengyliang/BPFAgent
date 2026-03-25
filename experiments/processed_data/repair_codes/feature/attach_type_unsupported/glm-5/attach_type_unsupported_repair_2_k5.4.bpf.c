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
static __always_inline void count_event(void) {
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&counter, &key);
    __u32 *target_tgid = bpf_map_lookup_elem(&cfg, &key);
    if (!val)
        return;
    if (target_tgid && *target_tgid) {
        __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        if (tgid != *target_tgid)
            return;
    }
    (*val)++;
}
SEC("kprobe/do_sys_open")
int BPF_KPROBE(attach_type_unsupported_kp) {
    count_event();
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_open")
int tp_sys_enter_open(struct trace_event_raw_sys_enter *ctx) {
    count_event();
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    count_event();
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
