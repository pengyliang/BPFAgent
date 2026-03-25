
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
    __type(value, __u32); /* 目标 TGID */
} cfg SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int check_verifier_logic(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&counter, &key);
    __u32 *target_tgid = bpf_map_lookup_elem(&cfg, &key);

    if (!val)
        return 0;

    /* 过滤特定进程，减少干扰 */
    if (target_tgid && *target_tgid) {
        __u32 cur = (__u32)(bpf_get_current_pid_tgid() >> 32);
        if (cur != *target_tgid)
            return 0;
    }

    
    
    u32 a = 10;
    
    /* 在栈上开辟空间 */
    char data[16] = {0};
    
    /* * 故意制造非对齐指针：
     * &data[0] 是对齐的，&data[1] 偏移了 1 字节。
     */
    __u64 *unaligned_ptr = (__u64 *)&data[1];

    /* * 测试点：直接对非对齐指针进行写操作
     * 预期：
     * - 旧内核：报 "misaligned stack access off=-15 size=8"
     * - 新内核：允许操作（或通过指令分解实现）
     */
    *unaligned_ptr = 0x123456789ABCDEF0;

    if (data[1] == 0xF0) {
        (*val)++;
    }
    
    (*val)++;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";