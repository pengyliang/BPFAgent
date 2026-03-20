#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int signo)
{
    (void)signo;
    g_stop = 1;
}

enum phase_kind {
    PHASE_LOAD = 1,
    PHASE_ATTACH = 2,
};

static enum phase_kind g_phase = PHASE_LOAD;

struct strbuf {
    char *data;
    size_t len;
    size_t cap;
};

static void sb_init(struct strbuf *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static void sb_free(struct strbuf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static void sb_append(struct strbuf *b, const char *s)
{
    size_t n;
    char *p;

    if (!s)
        return;
    n = strlen(s);
    if (n == 0)
        return;
    if (b->len + n + 1 > b->cap) {
        size_t new_cap = b->cap ? b->cap * 2 : 1024;
        while (new_cap < b->len + n + 1)
            new_cap *= 2;
        p = realloc(b->data, new_cap);
        if (!p)
            return;
        b->data = p;
        b->cap = new_cap;
    }
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static void sb_appendf(struct strbuf *b, const char *fmt, ...)
{
    char tmp[1024];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n <= 0)
        return;
    tmp[sizeof(tmp) - 1] = '\0';
    sb_append(b, tmp);
}

static void json_escape_to(FILE *out, const char *s)
{
    const unsigned char *p = (const unsigned char *)(s ? s : "");
    fputc('"', out);
    for (; *p; p++) {
        unsigned char c = *p;
        switch (c) {
        case '\\':
            fputs("\\\\", out);
            break;
        case '"':
            fputs("\\\"", out);
            break;
        case '\n':
            fputs("\\n", out);
            break;
        case '\r':
            fputs("\\r", out);
            break;
        case '\t':
            fputs("\\t", out);
            break;
        default:
            if (c < 0x20) {
                fprintf(out, "\\u%04x", (unsigned)c);
            } else {
                fputc((int)c, out);
            }
        }
    }
    fputc('"', out);
}

static struct strbuf g_load_stdout;
static struct strbuf g_load_stderr;
static struct strbuf g_attach_stdout;
static struct strbuf g_attach_stderr;

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    char tmp[1024];
    int n;
    (void)level;
    n = vsnprintf(tmp, sizeof(tmp), fmt, args);
    if (n <= 0)
        return 0;
    tmp[sizeof(tmp) - 1] = '\0';
    if (g_phase == PHASE_ATTACH)
        sb_append(&g_attach_stderr, tmp);
    else
        sb_append(&g_load_stderr, tmp);
    return 0;
}

static void print_phase_json(const char *phase, int ok, const char *stdout_text, const char *stderr_text,
                             const char *error_message)
{
    printf("PHASE_JSON {\"phase\":");
    json_escape_to(stdout, phase);
    printf(",\"ok\":%s,", ok ? "true" : "false");
    printf("\"stdout\":");
    json_escape_to(stdout, stdout_text);
    printf(",\"stderr\":");
    json_escape_to(stdout, stderr_text);
    printf(",\"error_message\":");
    json_escape_to(stdout, error_message ? error_message : "");
    printf("}\n");
    fflush(stdout);
}

static void dief(const char *fmt, ...)
{
    va_list ap;
    char msg[1024];
    int exit_code = 10;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    msg[sizeof(msg) - 1] = '\0';

    /* Mirror to stderr for humans. */
    fprintf(stderr, "%s\n", msg);

    if (g_phase == PHASE_ATTACH) {
        exit_code = 20;
        sb_appendf(&g_attach_stderr, "%s\n", msg);
        print_phase_json("load", 1, g_load_stdout.data, g_load_stderr.data, "");
        print_phase_json("attach", 0, g_attach_stdout.data, g_attach_stderr.data, msg);
    } else {
        sb_appendf(&g_load_stderr, "%s\n", msg);
        print_phase_json("load", 0, g_load_stdout.data, g_load_stderr.data, msg);
    }
    exit(exit_code);
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --obj <bpf_obj> --pin-path <bpffs_base_path>\n"
            "\n"
            "Behavior:\n"
            "- load BPF object via libbpf\n"
            "- attach all programs via bpf_program__attach()\n"
            "- pin all maps to <bpffs_base_path>_maps/\n"
            "- keep process alive until SIGINT/SIGTERM (attach lifetime = process lifetime)\n",
            prog);
}

static struct bpf_link *attach_program(struct bpf_program *prog, const char **prog_name_out,
                                       const char **sec_name_out, int *err_out)
{
    const char *prog_name = bpf_program__name(prog);
    const char *sec_name = bpf_program__section_name(prog);
    struct bpf_link *link;
    int err;

    if (!prog_name || !prog_name[0])
        prog_name = "prog";
    if (!sec_name || !sec_name[0])
        sec_name = "<unknown>";

    link = bpf_program__attach(prog);
    err = libbpf_get_error(link);
    if (err) {
        if (prog_name_out)
            *prog_name_out = prog_name;
        if (sec_name_out)
            *sec_name_out = sec_name;
        if (err_out)
            *err_out = err;
        return NULL;
    }

    if (prog_name_out)
        *prog_name_out = prog_name;
    if (sec_name_out)
        *sec_name_out = sec_name;
    if (err_out)
        *err_out = 0;
    return link;
}

static int parse_arg(int argc, char **argv, const char **obj_path, const char **pin_path)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--obj") && i + 1 < argc) {
            *obj_path = argv[++i];
        } else if (!strcmp(argv[i], "--pin-path") && i + 1 < argc) {
            *pin_path = argv[++i];
        } else {
            return -1;
        }
    }

    return (*obj_path && *pin_path) ? 0 : -1;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    const char *obj_path = NULL;
    const char *pin_path = NULL;
    struct bpf_link **links = NULL;
    int links_cap = 0;
    int links_cnt = 0;
    int err;
    char maps_dir[1024];

    if (parse_arg(argc, argv, &obj_path, &pin_path) < 0) {
        usage(argv[0]);
        return 2;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    sb_init(&g_load_stdout);
    sb_init(&g_load_stderr);
    sb_init(&g_attach_stdout);
    sb_init(&g_attach_stderr);
    libbpf_set_print(libbpf_print_fn);

    obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        dief("open failed: %s", obj_path);
    }

    err = bpf_object__load(obj);
    if (err) {
        dief("load failed: %d", err);
    }
    sb_appendf(&g_load_stdout, "loaded obj=%s\n", obj_path);

    /* Pin all maps so the runner can read them without bpftool. */
    snprintf(maps_dir, sizeof(maps_dir), "%s_maps", pin_path);
    err = bpf_object__pin_maps(obj, maps_dir);
    if (err) {
        dief("pin maps failed: dir=%s err=%d", maps_dir, err);
    }
    sb_appendf(&g_load_stdout, "pinned maps_dir=%s\n", maps_dir);

    /* Load phase is complete. */
    print_phase_json("load", 1, g_load_stdout.data, g_load_stderr.data, "");

    g_phase = PHASE_ATTACH;
    bpf_object__for_each_program(prog, obj) {
        const char *prog_name = NULL;
        const char *sec_name = NULL;
        struct bpf_link *link;
        int attach_err = 0;

        link = attach_program(prog, &prog_name, &sec_name, &attach_err);
        if (!link) {
            dief("attach failed: %s section=%s err=%d", prog_name, sec_name, attach_err);
        }
        sb_appendf(&g_attach_stdout, "attached prog=%s section=%s\n", prog_name, sec_name);

        if (links_cnt >= links_cap) {
            int new_cap = links_cap ? links_cap * 2 : 8;
            struct bpf_link **new_links = realloc(links, new_cap * sizeof(*new_links));
            if (!new_links)
                dief("oom");
            links = new_links;
            links_cap = new_cap;
        }
        links[links_cnt++] = link;
    }

    if (links_cnt == 0) {
        dief("no attachable program found in object");
    }

    print_phase_json("attach", 1, g_attach_stdout.data, g_attach_stderr.data, "");

    printf("READY pid=%d maps_dir=%s attached=%d\n", getpid(), maps_dir, links_cnt);
    fflush(stdout);

    while (!g_stop) {
        sleep(1);
    }

    for (int i = 0; i < links_cnt; i++) {
        bpf_link__destroy(links[i]);
    }
    free(links);
    bpf_object__close(obj);
    sb_free(&g_load_stdout);
    sb_free(&g_load_stderr);
    sb_free(&g_attach_stdout);
    sb_free(&g_attach_stderr);
    return 0;
}
