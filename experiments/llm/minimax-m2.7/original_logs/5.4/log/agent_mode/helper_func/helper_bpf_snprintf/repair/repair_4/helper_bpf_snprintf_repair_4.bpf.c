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

    if (!val)
        return 0;

    if (target_tgid && *target_tgid) {
        __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        if (tgid != *target_tgid)
            return 0;
    }

    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    /* Crutial block */
    char out[32];
    __builtin_memcpy(out, "pid=", 4);
    char *p = out + 4;
    if (pid >= 100000000) { *p++ = '0' + (pid / 100000000) % 10; if (pid >= 10000000) { *p++ = '0' + (pid / 10000000) % 10; if (pid >= 1000000) { *p++ = '0' + (pid / 1000000) % 10; if (pid >= 100000) { *p++ = '0' + (pid / 100000) % 10; if (pid >= 10000) { *p++ = '0' + (pid / 10000) % 10; if (pid >= 1000) { *p++ = '0' + (pid / 1000) % 10; if (pid >= 100) { *p++ = '0' + (pid / 100) % 10; if (pid >= 10) { *p++ = '0' + (pid / 10) % 10; }}}}}}}}
    *p++ = '0' + pid % 10;
    *p = '\0';
    bpf_trace_printk("%s", out);
    /* Crutial block end */
    (*val)++;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
