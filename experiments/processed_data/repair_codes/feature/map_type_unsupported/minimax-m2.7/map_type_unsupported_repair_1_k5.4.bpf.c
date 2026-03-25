#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
    __u64 ts;
};

/* Crutial block */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, 4);
    __uint(value_size, 4);
    __uint(max_entries, 1 << 12);
} events SEC(".maps");
/* Crutial block end */
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
int map_type_unsupported(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&counter, &key);
    __u32 *target_tgid = bpf_map_lookup_elem(&cfg, &key);
    struct event e = {};

    if (!val)
        return 0;

    if (target_tgid && *target_tgid) {
        __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        if (tgid != *target_tgid)
            return 0;
    }

    /**/
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    (*val)++;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
