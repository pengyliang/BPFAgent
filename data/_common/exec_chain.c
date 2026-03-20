// Single-PID execve chain to trigger sys_enter_execve (and fentry __x64_sys_execve).
// Re-execs itself N times with same PID/TGID.
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int get_count(const char *s)
{
    if (!s || !*s)
        return 1;
    int v = atoi(s);
    return v > 0 ? v : 1;
}

int main(int argc, char **argv)
{
    int count = 1;
    if (argc > 1)
        count = get_count(argv[1]);

    if (count <= 1)
        return 0;

    char next[32];
    snprintf(next, sizeof(next), "%d", count - 1);

    char *const new_argv[] = {argv[0], next, NULL};
    execv(argv[0], new_argv);
    fprintf(stderr, "execv failed: %s (%d)\n", strerror(errno), errno);
    return 1;
}

