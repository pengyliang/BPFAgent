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
int helper_arg_increase(struct trace_event_raw_sys_enter *ctx)
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
    out[0] = 'p'; out[1] = 'i'; out[2] = 'd'; out[3] = '=';
    out[4] = (data[0] / 100) ? '0' + (data[0] / 100) % 10 : (data[0] / 10) ? '0' + (data[0] / 10) % 10 : '0';
    out[5] = (data[0] / 100) ? '0' + (data[0] / 10) % 10 : (data[0] / 10) ? '0' + data[0] % 10 : (data[0] % 10) ? '0' + data[0] % 10 : '0';
    out[6] = (data[0] / 100) ? '0' + data[0] % 10 : (data[0] / 10) ? '0' : 0;
    out[7] = '\0';
    bpf_trace_printk("%s", out);
    /* Crutial block end */
    (*val)++;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
