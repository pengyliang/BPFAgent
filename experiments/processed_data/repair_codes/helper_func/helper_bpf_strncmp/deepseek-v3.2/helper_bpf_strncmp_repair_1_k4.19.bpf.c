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
const char expected_str[] = "ok";
static __always_inline long my_strncmp(const char *s1, __u32 n, const char *s2)
{
    char buf1[64];
    char buf2[64];
    long res = 0;
    __u32 i;
    
    if (bpf_probe_read(buf1, sizeof(buf1), s1) < 0)
        return -1;
    if (bpf_probe_read(buf2, sizeof(buf2), s2) < 0)
        return -1;
    
    for (i = 0; i < n; i++) {
        if (buf1[i] == '\0' || buf2[i] == '\0')
            break;
        if (buf1[i] != buf2[i]) {
            res = (long)buf1[i] - (long)buf2[i];
            break;
        }
    }
    
    return res;
}
SEC("tracepoint/syscalls/sys_enter_openat")
int helper_arg_decrease(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&counter, &key);
    __u32 *target_tgid = bpf_map_lookup_elem(&cfg, &key);
    const char s1[] = "ok";
    long ret;
    if (!val)
        return 0;
    if (target_tgid && *target_tgid) {
        __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        if (tgid != *target_tgid)
            return 0;
    }
    /* Crutial block */
    ret = my_strncmp(s1, sizeof(s1), expected_str);
    /* Crutial block end */
    if (ret == 0)
        (*val)++;
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
