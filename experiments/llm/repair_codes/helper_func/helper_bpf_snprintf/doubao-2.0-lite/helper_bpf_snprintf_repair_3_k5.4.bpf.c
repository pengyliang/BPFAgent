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
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    data[0] = pid;
    /* Crutial block */
    out[0] = 'p'; out[1] = 'i'; out[2] = 'd'; out[3] = '=';
    __u32 tmp = pid;
    int i = 4;
    if (tmp == 0) out[i++] = '0';
    else {
        char buf[10];
        int idx = 0;
        while (tmp && idx < 10) {
            buf[idx++] = '0' + (tmp % 10);
            tmp /= 10;
        }
        while (idx > 0 && i < 31) {
            out[i++] = buf[--idx];
        }
    }
    out[i++] = '\0';
    bpf_trace_printk("%s\n", out);
    /* Crutial block end */
    (*val)++;
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
