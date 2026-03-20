// Single-process write() loop to trigger sys_enter_write tracepoints.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *path = "/tmp/ebpf_agent_write_loop.tmp";
    int loops = 1;
    if (argc > 1)
        path = argv[1];
    if (argc > 2)
        loops = atoi(argv[2]);

    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    const char buf[] = "x";
    for (int i = 0; i < loops; i++) {
        if (write(fd, buf, sizeof(buf)) < 0) {
            perror("write");
            close(fd);
            return 1;
        }
    }
    close(fd);
    return 0;
}

