/* src/main.c - tlscap entry point */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <gelf.h>
#include "tlscap.skel.h"
#include "ssl_detect.h"
#include "event_reader.h"
#include "output.h"
#include "pcap_writer.h"
#include "keylog_writer.h"

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

/* Find symbol offset in ELF file.
 * For shared libraries: st_value is the file offset (works as-is).
 * For PIE executables: st_value is VMA, need to convert to file offset.
 * 
 * Note: LOAD segments are program headers (PT_LOAD), not section headers.
 */
static long find_symbol_offset(const char *path, const char *symbol)
{
    Elf *elf = NULL;
    int fd = -1;
    long offset = -1;
    unsigned long base_vaddr = 0;
    unsigned long base_offset = 0;
    int is_pie = 0;

    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "ELF library init failed\n");
        return -1;
    }

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        fprintf(stderr, "elf_begin failed: %s\n", elf_errmsg(-1));
        goto out;
    }

    GElf_Ehdr ehdr;
    if (!gelf_getehdr(elf, &ehdr)) {
        fprintf(stderr, "gelf_getehdr failed\n");
        goto out;
    }

    /* 
     * For both PIE (ET_DYN) and static executables (ET_EXEC), the symbol
     * addresses are virtual addresses, not file offsets. We need to
     * convert them to file offsets using the first LOAD segment.
     * Only for shared libraries (ET_DYN with entry=0) is st_value a file offset.
     */
    is_pie = (ehdr.e_type == ET_DYN && ehdr.e_entry != 0) || (ehdr.e_type == ET_EXEC);

    /* For PIE or static exec, find the first PT_LOAD segment to get base addresses */
    if (is_pie) {
        size_t phdr_num = ehdr.e_phnum;
        for (size_t i = 0; i < phdr_num; i++) {
            GElf_Phdr phdr;
            if (!gelf_getphdr(elf, i, &phdr))
                continue;
            /* PT_LOAD = 1 */
            if (phdr.p_type == 1 && base_vaddr == 0) {
                base_vaddr = phdr.p_vaddr;
                base_offset = phdr.p_offset;
                break;
            }
        }
    }

    /* Find the symbol in symtab or dynsym */
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr))
            continue;

        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
            continue;

        Elf_Data *data = elf_getdata(scn, NULL);
        if (!data)
            continue;

        int nsyms = shdr.sh_size / shdr.sh_entsize;
        for (int i = 0; i < nsyms; i++) {
            GElf_Sym sym;
            if (!gelf_getsym(data, i, &sym))
                continue;

            const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (name && strcmp(name, symbol) == 0) {
                unsigned long sym_vaddr = sym.st_value;
                
                if (is_pie && base_vaddr != 0) {
                    /* Convert VMA to file offset for PIE */
                    offset = (long)(sym_vaddr - base_vaddr + base_offset);
                } else {
                    /* For shared libraries, st_value is already the file offset */
                    offset = (long)sym_vaddr;
                }
                goto out;
            }
        }
    }

out:
    if (elf) elf_end(elf);
    if (fd >= 0) close(fd);
    return offset;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "tlscap - eBPF HTTPS plaintext capture tool\n\n"
        "Usage: %s [options]\n"
        "  -p PID    Capture only from this PID\n"
        "  -l PATH   Path to libssl.so (default: auto-detect)\n"
        "  -b SIZE   Ring buffer size in MB (default: 4)\n"
        "  -w FILE   Write output to PCAP file for Wireshark\n"
        "  -k FILE   Write TLS keylog file for Wireshark decryption\n"
        "  -v        Verbose output\n"
        "  -h        Show help\n", prog);
}

int main(int argc, char **argv)
{
    int target_pid_val = 0;
    const char *libssl_path_arg = NULL;
    const char *pcap_path = NULL;
    const char *keylog_path = NULL;
    int ringbuf_mb = 4;
    int verbose = 0;
    int opt;

    while ((opt = getopt(argc, argv, "p:l:b:w:k:vh")) != -1) {
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
            if (ringbuf_mb & (ringbuf_mb - 1)) {
                fprintf(stderr, "Error: buffer size must be a power of 2 (1, 2, 4, 8, ...)\n");
                return 1;
            }
            break;
        case 'v':
            verbose = 1;
            break;
        case 'w':
            pcap_path = optarg;
            break;
        case 'k':
            keylog_path = optarg;
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

    /* Attach uprobes to libssl.so or executable with static OpenSSL */
    int attach_pid = target_pid_val > 0 ? target_pid_val : -1;

    /* Find symbol offsets (works for both .so and static executable) */
    long ssl_write_offset = find_symbol_offset(libssl_path, "SSL_write");
    long ssl_read_offset = find_symbol_offset(libssl_path, "SSL_read");

    if (ssl_write_offset < 0) {
        fprintf(stderr, "Error: cannot find SSL_write symbol in %s\n", libssl_path);
        goto cleanup;
    }
    if (ssl_read_offset < 0) {
        fprintf(stderr, "Error: cannot find SSL_read symbol in %s\n", libssl_path);
        goto cleanup;
    }
    if (verbose) {
        fprintf(stderr, "SSL_write offset: 0x%lx\n", ssl_write_offset);
        fprintf(stderr, "SSL_read offset: 0x%lx\n", ssl_read_offset);
    }

    LIBBPF_OPTS(bpf_uprobe_opts, opts);

    opts.retprobe = false;
    if (verbose)
        fprintf(stderr, "Attaching uprobe to SSL_write at offset 0x%lx (pid=%d)...\n",
                ssl_write_offset, attach_pid);
    skel->links.ssl_write_entry = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_write_entry, attach_pid, libssl_path,
        ssl_write_offset, &opts);
    if (!skel->links.ssl_write_entry) {
        fprintf(stderr, "Error: failed to attach uprobe to SSL_write: %s (errno=%d)\n",
                strerror(errno), errno);
        goto cleanup;
    }
    if (verbose)
        fprintf(stderr, "Successfully attached uprobe to SSL_write\n");

    opts.retprobe = true;
    skel->links.ssl_write_return = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_write_return, attach_pid, libssl_path,
        ssl_write_offset, &opts);
    if (!skel->links.ssl_write_return) {
        fprintf(stderr, "Error: failed to attach uretprobe to SSL_write: %s\n",
                strerror(errno));
        goto cleanup;
    }

    opts.retprobe = false;
    skel->links.ssl_read_entry = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_read_entry, attach_pid, libssl_path,
        ssl_read_offset, &opts);
    if (!skel->links.ssl_read_entry) {
        fprintf(stderr, "Error: failed to attach uprobe to SSL_read: %s\n",
                strerror(errno));
        goto cleanup;
    }

    opts.retprobe = true;
    skel->links.ssl_read_return = bpf_program__attach_uprobe_opts(
        skel->progs.ssl_read_return, attach_pid, libssl_path,
        ssl_read_offset, &opts);
    if (!skel->links.ssl_read_return) {
        fprintf(stderr, "Error: failed to attach uretprobe to SSL_read: %s\n",
                strerror(errno));
        goto cleanup;
    }

    /* Try to attach SSL_write_ex and SSL_read_ex (optional, may not exist) */
    long ssl_write_ex_offset = find_symbol_offset(libssl_path, "SSL_write_ex");
    long ssl_read_ex_offset = find_symbol_offset(libssl_path, "SSL_read_ex");

    if (ssl_write_ex_offset >= 0) {
        if (verbose)
            fprintf(stderr, "SSL_write_ex offset: 0x%lx\n", ssl_write_ex_offset);
        opts.retprobe = false;
        skel->links.ssl_write_ex_entry = bpf_program__attach_uprobe_opts(
            skel->progs.ssl_write_ex_entry, attach_pid, libssl_path,
            ssl_write_ex_offset, &opts);
        if (!skel->links.ssl_write_ex_entry) {
            fprintf(stderr, "Warning: failed to attach uprobe to SSL_write_ex: %s\n",
                    strerror(errno));
        } else {
            opts.retprobe = true;
            skel->links.ssl_write_ex_return = bpf_program__attach_uprobe_opts(
                skel->progs.ssl_write_ex_return, attach_pid, libssl_path,
                ssl_write_ex_offset, &opts);
            if (!skel->links.ssl_write_ex_return) {
                fprintf(stderr, "Warning: failed to attach uretprobe to SSL_write_ex: %s\n",
                        strerror(errno));
            }
        }
    }

    if (ssl_read_ex_offset >= 0) {
        if (verbose)
            fprintf(stderr, "SSL_read_ex offset: 0x%lx\n", ssl_read_ex_offset);
        opts.retprobe = false;
        skel->links.ssl_read_ex_entry = bpf_program__attach_uprobe_opts(
            skel->progs.ssl_read_ex_entry, attach_pid, libssl_path,
            ssl_read_ex_offset, &opts);
        if (!skel->links.ssl_read_ex_entry) {
            fprintf(stderr, "Warning: failed to attach uprobe to SSL_read_ex: %s\n",
                    strerror(errno));
        } else {
            opts.retprobe = true;
            skel->links.ssl_read_ex_return = bpf_program__attach_uprobe_opts(
                skel->progs.ssl_read_ex_return, attach_pid, libssl_path,
                ssl_read_ex_offset, &opts);
            if (!skel->links.ssl_read_ex_return) {
                fprintf(stderr, "Warning: failed to attach uretprobe to SSL_read_ex: %s\n",
                        strerror(errno));
            }
        }
    }

    /* Try to attach SSL_do_handshake for master secret extraction */
    long ssl_do_handshake_offset = find_symbol_offset(libssl_path, "SSL_do_handshake");
    if (ssl_do_handshake_offset >= 0) {
        if (verbose)
            fprintf(stderr, "SSL_do_handshake offset: 0x%lx\n", ssl_do_handshake_offset);
        opts.retprobe = false;
        skel->links.ssl_do_handshake_entry = bpf_program__attach_uprobe_opts(
            skel->progs.ssl_do_handshake_entry, attach_pid, libssl_path,
            ssl_do_handshake_offset, &opts);
        if (!skel->links.ssl_do_handshake_entry) {
            fprintf(stderr, "Warning: failed to attach uprobe to SSL_do_handshake: %s\n",
                    strerror(errno));
        } else {
            if (verbose)
                fprintf(stderr, "Successfully attached uprobe to SSL_do_handshake\n");
        }
    } else {
        if (verbose)
            fprintf(stderr, "SSL_do_handshake not found, keylog extraction disabled\n");
    }

    /* Setup output and event reader */
    output_init();

    /* Initialize PCAP writer if -w was specified */
    if (pcap_path) {
        if (pcap_writer_init(pcap_path) != 0) {
            fprintf(stderr, "Error: failed to initialize PCAP writer\n");
            goto cleanup;
        }
    }

    /* Initialize keylog writer if -k was specified */
    if (keylog_path) {
        if (keylog_writer_init(keylog_path) != 0) {
            fprintf(stderr, "Error: failed to initialize keylog writer\n");
            goto cleanup;
        }
    }

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
    pcap_writer_close();
    keylog_writer_close();
    tlscap_bpf__destroy(skel);
    return 0;

cleanup:
    pcap_writer_close();
    keylog_writer_close();
    tlscap_bpf__destroy(skel);
    return 1;
}
