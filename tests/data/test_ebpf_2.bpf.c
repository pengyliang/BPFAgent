// ringbuf_test_kern.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct event {
    int pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} events SEC(".maps");

SEC("kprobe/__x64_sys_execve")
int handle_exec(struct pt_regs *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";