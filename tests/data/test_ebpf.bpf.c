// execve_kern.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, long);
} counter SEC(".maps");

SEC("kprobe/__x64_sys_execve")
int count_execve(struct pt_regs *ctx)
{
    int key = 0;
    long *value;

    value = bpf_map_lookup_elem(&counter, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";