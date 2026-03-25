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
    __builtin_memcpy(out, "pid=", 4);
    __u32 pid = data[0];
    char *p = out + 4;
    __u32 div = 1000000000;
    int started = 0;
    while (div > 0) {
        if (pid >= div || started || div == 1) {
            *p++ = '0' + (pid / div) % 10;
            started = 1;
        }
        div /= 10;
    }
    *p = '\0';
    bpf_trace_printk("%s", out);
    /* Crutial block end */
    (*val)++;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
