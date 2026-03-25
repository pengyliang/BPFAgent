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
static __always_inline long my_strncmp(const char *s1, __u32 n, const char *s2)
{
    char buf1[64];
    char buf2[64];
    long res = 0;
    __u32 i;
    __u32 max_len;
    char c1, c2;
    
    /* 边界检查：确保源指针不为空 */
    if (!s1 || !s2)
        return -1;
    
    /* 限制读取长度不超过缓冲区大小 */
    max_len = sizeof(buf1) < n ? sizeof(buf1) : n;
    if (max_len == 0)
        return 0;
    
    /* 使用明确的边界检查进行读取 */
    if (bpf_probe_read(buf1, max_len, s1) < 0)
        return -1;
    if (bpf_probe_read(buf2, max_len, s2) < 0)
        return -1;
    
    /* 简化循环比较逻辑 */
    for (i = 0; i < max_len; i++) {
        c1 = buf1[i];
        c2 = buf2[i];
        
        if (c1 == '\0' || c2 == '\0')
            break;
            
        if (c1 != c2) {
            res = (long)c1 - (long)c2;
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
    const char expected_str_local[] = "ok";
    long ret;
    if (!val)
        return 0;
    if (target_tgid && *target_tgid) {
        __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        if (tgid != *target_tgid)
            return 0;
    }
    /* Crutial block */
    ret = my_strncmp(s1, sizeof(s1), expected_str_local);
    /* Crutial block end */
    if (ret == 0)
        (*val)++;
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
