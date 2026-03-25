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

static __always_inline int global_add_stress(__u64 *val, __u64 x)
{
    if (!val)
        return 0;

    /*
     * Multiple independent branches on unknown scalar 'x' to blow up states.
     * Each bit check introduces a verifier split.
     */
    if (x & (1ull << 0))
        (*val) += 1;
    else
        (*val) += 2;

    if (x & (1ull << 1))
        (*val) += 4;
    else
        (*val) += 8;

    if (x & (1ull << 2))
        (*val) += 16;
    else
        (*val) += 32;

    if (x & (1ull << 3))
        (*val) += 64;
    else
        (*val) += 128;
    if (x & (1ull << 4))
        (*val) += 256;
    else
        (*val) += 512;

    if (x & (1ull << 5))
        (*val) += 1024;
    else
        (*val) += 2048;

    if (x & (1ull << 6))
        (*val) += 4096;
    else
        (*val) += 8192;

    if (x & (1ull << 7))
        (*val) += 16384;
    else
        (*val) += 32768;

    if (x & (1ull << 8))
        (*val) += 65536;
    else
        (*val) += 131072;

    if (x & (1ull << 9))
        (*val) += 262144;
    else
        (*val) += 524288;

    return 1;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int bpf_to_bpf_fault(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&counter, &key);
    __u32 *target_tgid = bpf_map_lookup_elem(&cfg, &key);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 x = pid_tgid;  // verifier cannot predict this unknown scalar

    if (!val)
        return 0;

    if (target_tgid && *target_tgid) {
        __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        if (tgid != *target_tgid)
            return 0;
    }

    /* Crutial block */
    __u32 max_time = 50;
    __u32 i = 0;
#pragma unroll
    for (i = 0; i < max_time; i++) {
        global_add_stress(val, x + i);
    }
    /* Crutial block end */


    return 0;
}

char LICENSE[] SEC("license") = "GPL";
