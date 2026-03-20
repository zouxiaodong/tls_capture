/* src/main.c - tlscap entry point */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tlscap.skel.h"
#include "ssl_detect.h"
#include "event_reader.h"
#include "output.h"

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "tlscap - eBPF HTTPS plaintext capture tool\n\n"
        "Usage: %s [options]\n"
        "  -p PID    Capture only from this PID\n"
        "  -l PATH   Path to libssl.so (default: auto-detect)\n"
        "  -b SIZE   Ring buffer size in MB (default: 4)\n"
        "  -v        Verbose output\n"
        "  -h        Show help\n", prog);
}

int main(int argc, char **argv)
{
    int target_pid_val = 0;
    const char *libssl_path_arg = NULL;
    int ringbuf_mb = 4;
    int verbose = 0;
    int opt;

    while ((opt = getopt(argc, argv, "p:l:b:vh")) != -1) {
        switch (opt) {
        case 'p':
            target_pid_val = atoi(optarg);
            if (target_pid_val <= 0) {
                fprintf(stderr, "Error: invalid PID: %s\n", optarg);
                return 1;
            }
            break;
        case 'l':
            libssl_path_arg = optarg;
            break;
        case 'b':
            ringbuf_mb = atoi(optarg);
            if (ringbuf_mb <= 0) {
                fprintf(stderr, "Error: invalid buffer size: %s\n", optarg);
                return 1;
            }
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Error: tlscap requires root privileges.\n");
        return 1;
    }

    /* Detect libssl.so */
    char libssl_path[256];
    if (ssl_detect(target_pid_val, libssl_path_arg,
                   libssl_path, sizeof(libssl_path)) != 0) {
        fprintf(stderr,
            "Error: cannot find libssl.so. Use -l to specify the path.\n");
        return 1;
    }
    if (verbose)
        fprintf(stderr, "Using libssl: %s\n", libssl_path);

    /* Open BPF skeleton */
    struct tlscap_bpf *skel = tlscap_bpf__open();
    if (!skel) {
        fprintf(stderr, "Error: failed to open BPF program: %s\n",
                strerror(errno));
        return 1;
    }

    /* Configure ring buffer size before load */
    bpf_map__set_max_entries(skel->maps.events,
                             ringbuf_mb * 1024 * 1024);

    /* Load BPF program */
    int err = tlscap_bpf__load(skel);
    if (err) {
        fprintf(stderr,
            "Error: failed to load BPF program: %s\n"
            "Hint: check kernel version (>= 5.10) and BTF support.\n",
            strerror(-err));
        tlscap_bpf__destroy(skel);
        return 1;
    }

    /* Set target PID filter */
    if (target_pid_val > 0) {
        __u32 key = 0;
        __u32 val = (__u32)target_pid_val;
        int fd = bpf_map__fd(skel->maps.target_pid);
        bpf_map_update_elem(fd, &key, &val, BPF_ANY);
    }

    /* Attach uprobes to libssl.so */
    int attach_pid = target_pid_val > 0 ? target_pid_val : -1;

    LIBBPF_OPTS(bpf_uprobe_opts, opts);

    opts.func_name = "SSL_write";
    opts.retprobe = false;
    skel->links.ssl_write_entry = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_write_entry, attach_pid, libssl_path, 0, &opts);
    if (!skel->links.ssl_write_entry) {
        fprintf(stderr, "Error: failed to attach uprobe to SSL_write: %s\n"
                "Hint: SSL_write symbol may be stripped, or OpenSSL may be "
                "statically linked.\n", strerror(errno));
        goto cleanup;
    }

    opts.retprobe = true;
    skel->links.ssl_write_return = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_write_return, attach_pid, libssl_path, 0, &opts);
    if (!skel->links.ssl_write_return) {
        fprintf(stderr, "Error: failed to attach uretprobe to SSL_write: %s\n",
                strerror(errno));
        goto cleanup;
    }

    opts.func_name = "SSL_read";
    opts.retprobe = false;
    skel->links.ssl_read_entry = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_read_entry, attach_pid, libssl_path, 0, &opts);
    if (!skel->links.ssl_read_entry) {
        fprintf(stderr, "Error: failed to attach uprobe to SSL_read: %s\n"
                "Hint: SSL_read symbol may be stripped, or OpenSSL may be "
                "statically linked.\n", strerror(errno));
        goto cleanup;
    }

    opts.retprobe = true;
    skel->links.ssl_read_return = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_read_return, attach_pid, libssl_path, 0, &opts);
    if (!skel->links.ssl_read_return) {
        fprintf(stderr, "Error: failed to attach uretprobe to SSL_read: %s\n",
                strerror(errno));
        goto cleanup;
    }

    /* Setup output and event reader */
    output_init();
    struct ring_buffer *rb = event_reader_create(
        bpf_map__fd(skel->maps.events));
    if (!rb) {
        fprintf(stderr, "Error: failed to create ring buffer reader\n");
        goto cleanup;
    }

    /* Signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    fprintf(stderr, "tlscap started. Capturing TLS traffic from %s...\n",
            libssl_path);
    if (target_pid_val > 0)
        fprintf(stderr, "Filtering PID: %d\n", target_pid_val);
    fprintf(stderr, "Press Ctrl+C to stop.\n\n");

    /* Event loop */
    while (running) {
        err = event_reader_poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
        unsigned long lost = event_reader_get_lost();
        if (lost > 0)
            fprintf(stderr, "[WARNING: %lu events dropped]\n", lost);
    }

    fprintf(stderr, "\ntlscap stopped.\n");
    event_reader_destroy(rb);
    tlscap_bpf__destroy(skel);
    return 0;

cleanup:
    tlscap_bpf__destroy(skel);
    return 1;
}
