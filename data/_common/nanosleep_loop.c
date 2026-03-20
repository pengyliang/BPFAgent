// Single-process nanosleep loop to trigger clock_nanosleep/nanosleep syscalls.
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv)
{
    int loops = 3;
    if (argc > 1)
        loops = atoi(argv[1]);
    if (loops <= 0)
        loops = 1;

    struct timespec ts = {.tv_sec = 0, .tv_nsec = 1000000}; /* 1ms */
    for (int i = 0; i < loops; i++) {
        if (nanosleep(&ts, NULL) != 0) {
            fprintf(stderr, "nanosleep failed: %s (%d)\n", strerror(errno), errno);
            return 1;
        }
    }
    return 0;
}

