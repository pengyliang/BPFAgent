#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s lookup-u64 --map-pin <bpffs_map_path> --key-u32 <key>\n"
            "  %s update-u32 --map-pin <bpffs_map_path> --key-u32 <key> --value-u32 <value>\n",
            prog, prog);
}

static int parse_u32(const char *s, __u32 *out)
{
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 0);
    if (!s || !*s || !end || *end != '\0' || v > 0xffffffffUL)
        return -1;
    *out = (__u32)v;
    return 0;
}

int main(int argc, char **argv)
{
    const char *cmd = NULL;
    const char *map_pin = NULL;
    __u32 key_u32 = 0;
    int have_key = 0;
    __u32 value_u32 = 0;
    int have_value = 0;

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    cmd = argv[1];

    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--map-pin") && i + 1 < argc) {
            map_pin = argv[++i];
        } else if (!strcmp(argv[i], "--key-u32") && i + 1 < argc) {
            if (parse_u32(argv[++i], &key_u32) != 0) {
                fprintf(stderr, "invalid --key-u32\n");
                return 2;
            }
            have_key = 1;
        } else if (!strcmp(argv[i], "--value-u32") && i + 1 < argc) {
            if (parse_u32(argv[++i], &value_u32) != 0) {
                fprintf(stderr, "invalid --value-u32\n");
                return 2;
            }
            have_value = 1;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (!map_pin || !have_key) {
        usage(argv[0]);
        return 2;
    }

    if (strcmp(cmd, "lookup-u64") != 0 && strcmp(cmd, "update-u32") != 0) {
        usage(argv[0]);
        return 2;
    }

    int fd = bpf_obj_get(map_pin);
    if (fd < 0) {
        fprintf(stderr, "bpf_obj_get failed: %s (%d)\n", strerror(errno), errno);
        return 1;
    }

    if (strcmp(cmd, "lookup-u64") == 0) {
        __u64 value = 0;
        if (bpf_map_lookup_elem(fd, &key_u32, &value) != 0) {
            fprintf(stderr, "bpf_map_lookup_elem failed: %s (%d)\n", strerror(errno), errno);
            close(fd);
            return 1;
        }
        close(fd);
        printf("{\"key\":%u,\"value\":%llu}\n", key_u32, (unsigned long long)value);
        return 0;
    }

    /* update-u32 */
    if (!have_value) {
        usage(argv[0]);
        close(fd);
        return 2;
    }
    if (bpf_map_update_elem(fd, &key_u32, &value_u32, BPF_ANY) != 0) {
        fprintf(stderr, "bpf_map_update_elem failed: %s (%d)\n", strerror(errno), errno);
        close(fd);
        return 1;
    }
    close(fd);
    printf("{\"key\":%u,\"value\":%u}\n", key_u32, value_u32);
    return 0;
}

