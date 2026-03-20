#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * Verifier compatibility stressor (no overlap with other verifier cases):
 *
 * Goal: make older kernels (e.g. 5.4) more likely to fail at load time due to
 * verifier state explosion / complexity limits, while newer kernels (e.g. 5.15)
 * are more likely to pass thanks to verifier improvements and per-subprog caching.
 *
 * This is intentionally *not* a feature-gate (no new map types/helpers/prog types).
 */
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

__noinline int global_add_stress(__u64 *val, __u64 x)
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
    /* ctx->args[0] is an unknown scalar from verifier perspective */
    __u64 x = ctx ? (__u64)ctx->args[0] : 0;

    if (!val)
        return 0;

    if (target_tgid && *target_tgid) {
        __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        if (tgid != *target_tgid)
            return 0;
    }

    /*
     * Many call sites into the same global subprogram with different x,
     * multiplying state exploration.
     */
    global_add_stress(val, x + 0);
    global_add_stress(val, x + 1);
    global_add_stress(val, x + 2);
    global_add_stress(val, x + 3);
    global_add_stress(val, x + 4);
    global_add_stress(val, x + 5);
    global_add_stress(val, x + 6);
    global_add_stress(val, x + 7);
    global_add_stress(val, x + 8);
    global_add_stress(val, x + 9);
    global_add_stress(val, x + 10);
    global_add_stress(val, x + 11);
    global_add_stress(val, x + 12);
    global_add_stress(val, x + 13);
    global_add_stress(val, x + 14);
    global_add_stress(val, x + 15);
    global_add_stress(val, x + 16);
    global_add_stress(val, x + 17);
    global_add_stress(val, x + 18);
    global_add_stress(val, x + 19);
    global_add_stress(val, x + 20);
    global_add_stress(val, x + 21);
    global_add_stress(val, x + 22);
    global_add_stress(val, x + 23);
    global_add_stress(val, x + 24);
    global_add_stress(val, x + 25);
    global_add_stress(val, x + 26);
    global_add_stress(val, x + 27);
    global_add_stress(val, x + 28);
    global_add_stress(val, x + 29);
    global_add_stress(val, x + 30);
    global_add_stress(val, x + 31);
    global_add_stress(val, x + 32);
    global_add_stress(val, x + 33);
    global_add_stress(val, x + 34);
    global_add_stress(val, x + 35);
    global_add_stress(val, x + 36);
    global_add_stress(val, x + 37);
    global_add_stress(val, x + 38);
    global_add_stress(val, x + 39);
    global_add_stress(val, x + 40);
    global_add_stress(val, x + 41);
    global_add_stress(val, x + 42);
    global_add_stress(val, x + 43);
    global_add_stress(val, x + 44);
    global_add_stress(val, x + 45);
    global_add_stress(val, x + 46);
    global_add_stress(val, x + 47);
    global_add_stress(val, x + 48);
    global_add_stress(val, x + 49);
    global_add_stress(val, x + 50);
    global_add_stress(val, x + 51);
    global_add_stress(val, x + 52);
    global_add_stress(val, x + 53);
    global_add_stress(val, x + 54);
    global_add_stress(val, x + 55);
    global_add_stress(val, x + 56);
    global_add_stress(val, x + 57);
    global_add_stress(val, x + 58);
    global_add_stress(val, x + 59);
    global_add_stress(val, x + 60);
    global_add_stress(val, x + 61);
    global_add_stress(val, x + 62);
    global_add_stress(val, x + 63);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
