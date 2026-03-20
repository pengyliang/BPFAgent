// Minimal openat2 loop for workload noise isolation.
// Builds with plain libc; triggers do_sys_openat2.
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

struct open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

static int do_openat2(const char *path)
{
#ifdef __NR_openat2
    struct open_how how = {};
    int fd = (int)syscall(__NR_openat2, AT_FDCWD, path, &how, sizeof(how));
    return fd;
#else
    errno = ENOSYS;
    return -1;
#endif
}

int main(int argc, char **argv)
{
    const char *path = "/etc/hostname";
    int loops = 3;
    if (argc > 1)
        path = argv[1];
    if (argc > 2)
        loops = atoi(argv[2]);

    for (int i = 0; i < loops; i++) {
        int fd = do_openat2(path);
        if (fd < 0) {
            fprintf(stderr, "openat2 failed: %s (%d)\n", strerror(errno), errno);
            return 1;
        }
        close(fd);
    }
    return 0;
}

