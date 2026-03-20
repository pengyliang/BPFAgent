// Single-process open() loop to trigger sys_enter_openat tracepoints.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *path = "/etc/hostname";
    int loops = 3;
    if (argc > 1)
        path = argv[1];
    if (argc > 2)
        loops = atoi(argv[2]);

    for (int i = 0; i < loops; i++) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            perror("open");
            return 1;
        }
        close(fd);
    }
    return 0;
}

