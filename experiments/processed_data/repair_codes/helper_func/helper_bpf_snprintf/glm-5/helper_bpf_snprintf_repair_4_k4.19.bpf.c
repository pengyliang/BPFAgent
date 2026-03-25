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
/* Compatibility wrapper for bpf_snprintf */
#define bpf_snprintf(out, size, fmt, data, dsize) \
    bpf_probe_read(out, size, fmt)
SEC("tracepoint/syscalls/sys_enter_openat")
int helper_arg_increase(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&counter, &key);
    __u32 *target_tgid = bpf_map_lookup_elem(&cfg, &key);
    char out[32];
    __u64 data[1];
    long n;
    if (!val)
        return 0;
    if (target_tgid && *target_tgid) {
        __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        if (tgid != *target_tgid)
            return 0;
    }
    data[0] = (__u32)(bpf_get_current_pid_tgid() >> 32);
    /* Crutial block */
    n = bpf_snprintf(out, sizeof(out), fmt_str, data, sizeof(data));
    /* Crutial block end */
    if (n > 0)
        (*val)++;
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
