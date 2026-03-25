#include <linux/types.h>
#include <linux/bpf.h>
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

const char fmt_str[] = "pid=%d";

SEC("tracepoint/syscalls/sys_enter_openat")
int helper_arg_increase(void *ctx)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&counter, &key);
    __u32 *target_tgid = bpf_map_lookup_elem(&cfg, &key);
    char out[32];
    __u64 data[1];

    if (!val)
        return 0;

    if (target_tgid && *target_tgid) {
        __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        if (tgid != *target_tgid)
            return 0;
    }

    data[0] = (__u32)(bpf_get_current_pid_tgid() >> 32);
    /* Crutial block */
    bpf_snprintf(out, sizeof(out), fmt_str, data, sizeof(data));
    bpf_trace_printk("%s", out);
    /* Crutial block end */
    (*val)++;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
