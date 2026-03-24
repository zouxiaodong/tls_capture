// SPDX-License-Identifier: GPL-2.0
// src/bpf/tlscap.bpf.c - eBPF probes for SSL_read/SSL_write

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "tlscap.h"

char LICENSE[] SEC("license") = "GPL";

/* --- Maps --- */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct ssl_args);
} ssl_read_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct ssl_args);
} ssl_write_args SEC(".maps");

/* Separate maps for _ex variants */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct ssl_args);
} ssl_read_ex_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct ssl_args);
} ssl_write_ex_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid SEC(".maps");

/* --- Helpers --- */

static __always_inline int check_target_pid(void)
{
    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(&target_pid, &key);
    if (val && *val != 0) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        if (pid != *val)
            return 0;
    }
    return 1;
}

static __always_inline int process_ssl_return(
    void *map, __u32 evt_type, int ret_val)
{
    if (ret_val <= 0)
        return 0;

    /* Save ret_val early and bound it for the verifier.
     * The key insight: ret_val comes from PT_REGS_RC which may be signed,
     * but we've already checked ret_val > 0. We need to explicitly bound it
     * using bitwise AND so verifier knows the value is non-negative.
     */
    __u32 len = ret_val & (MAX_DATA_SIZE - 1);
    __u32 orig_len = ret_val;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args *args = bpf_map_lookup_elem(map, &pid_tgid);
    if (!args)
        return 0;

    struct ssl_args saved = *args;
    bpf_map_delete_elem(map, &pid_tgid);

    struct tls_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->pid = pid_tgid >> 32;
    evt->tid = (__u32)pid_tgid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->type = evt_type;
    evt->ssl_ptr = saved.ssl_ptr;
    evt->truncated = 0;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    /* Record original length for data_len */
    evt->data_len = orig_len;
    if (orig_len >= MAX_DATA_SIZE) {
        evt->truncated = 1;
    }

    /* len is already bounded by the bitwise AND above */
    barrier_var(len);

    if (bpf_probe_read_user(evt->data, len, (void *)saved.buf) != 0)
        evt->data_len = 0;

    evt->data[len] = '\0';

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* Process SSL_read_ex/SSL_write_ex return.
 * These functions return 1 on success, 0 on failure.
 * The actual byte count is stored at bytes_ptr (4th argument).
 */
static __always_inline int process_ssl_ex_return(
    void *map, __u32 evt_type, int ret_val)
{
    /* SSL_read_ex/SSL_write_ex return 1 on success, 0 on failure */
    if (ret_val != 1)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args *args = bpf_map_lookup_elem(map, &pid_tgid);
    if (!args)
        return 0;

    struct ssl_args saved = *args;
    bpf_map_delete_elem(map, &pid_tgid);

    /* Read the actual byte count from bytes_ptr */
    size_t bytes_count = 0;
    if (bpf_probe_read_user(&bytes_count, sizeof(size_t),
                            (void *)saved.bytes_ptr) != 0 || bytes_count == 0)
        return 0;

    __u32 len = bytes_count & (MAX_DATA_SIZE - 1);
    __u32 orig_len = bytes_count;

    struct tls_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->pid = pid_tgid >> 32;
    evt->tid = (__u32)pid_tgid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->type = evt_type;
    evt->ssl_ptr = saved.ssl_ptr;
    evt->truncated = 0;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    evt->data_len = orig_len;
    if (orig_len >= MAX_DATA_SIZE) {
        evt->truncated = 1;
    }

    barrier_var(len);

    if (bpf_probe_read_user(evt->data, len, (void *)saved.buf) != 0)
        evt->data_len = 0;

    evt->data[len] = '\0';

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* --- SSL_write probes --- */

SEC("uprobe")
int ssl_write_entry(struct pt_regs *ctx)
{
    if (!check_target_pid())
        return 0;

    void *ssl = (void *)PT_REGS_PARM1(ctx);
    const void *buf = (const void *)PT_REGS_PARM2(ctx);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args args = {
        .buf = (__u64)buf,
        .ssl_ptr = (__u64)ssl,
    };
    bpf_map_update_elem(&ssl_write_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int ssl_write_return(struct pt_regs *ctx)
{
    if (!check_target_pid())
        return 0;
    int ret = (int)PT_REGS_RC(ctx);
    return process_ssl_return(&ssl_write_args, EVENT_SSL_WRITE, ret);
}

/* --- SSL_read probes --- */

SEC("uprobe")
int ssl_read_entry(struct pt_regs *ctx)
{
    if (!check_target_pid())
        return 0;

    void *ssl = (void *)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args args = {
        .buf = (__u64)buf,
        .ssl_ptr = (__u64)ssl,
    };
    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int ssl_read_return(struct pt_regs *ctx)
{
    if (!check_target_pid())
        return 0;
    int ret = (int)PT_REGS_RC(ctx);
    return process_ssl_return(&ssl_read_args, EVENT_SSL_READ, ret);
}

/* --- SSL_write_ex probes --- */

SEC("uprobe")
int ssl_write_ex_entry(struct pt_regs *ctx)
{
    if (!check_target_pid())
        return 0;

    void *ssl = (void *)PT_REGS_PARM1(ctx);
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    /* PARM3 is num (size_t) */
    void *written_ptr = (void *)PT_REGS_PARM4(ctx);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args args = {
        .buf = (__u64)buf,
        .ssl_ptr = (__u64)ssl,
        .bytes_ptr = (__u64)written_ptr,
    };
    bpf_map_update_elem(&ssl_write_ex_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int ssl_write_ex_return(struct pt_regs *ctx)
{
    if (!check_target_pid())
        return 0;
    int ret = (int)PT_REGS_RC(ctx);
    return process_ssl_ex_return(&ssl_write_ex_args, EVENT_SSL_WRITE, ret);
}

/* Master secret extraction - TLS 1.2 */
/* These are estimated offsets - actual offsets vary by OpenSSL version */
/* SSL3_STATE (s3) offset from SSL struct - typically 0x78 or 0x80 */
#define SSL_S3_OFFSET         0x78
/* master_key offset in s3 - typically 0x98 or 0x100 */
#define MASTER_KEY_OFFSET     0x98
/* client_random offset in s3 - typically 0x10 */
#define CLIENT_RANDOM_OFFSET  0x10
/* version offset in s3 - typically 0x8 */
#define VERSION_OFFSET        0x08

/* TLS constants */
#define TLS_CLIENT_RANDOM_SIZE 32
#define TLS_MASTER_SECRET_SIZE 48
#define EVENT_MASTER_SECRET 2

struct master_secret_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp_ns;
    __u32 type;
    __u32 version;
    __u32 cipher_id;
    __u8  client_random[TLS_CLIENT_RANDOM_SIZE];
    __u8  master_secret[TLS_MASTER_SECRET_SIZE];
    __u8  is_client;
    char  comm[16];
};

/* --- Master secret extraction probes --- */

SEC("uprobe")
int ssl_do_handshake_entry(struct pt_regs *ctx)
{
    if (!check_target_pid())
        return 0;

    void *ssl = (void *)PT_REGS_PARM1(ctx);
    if (!ssl)
        return 0;

    /* Try to extract master secret from SSL structure */
    /* Navigate: SSL -> s3 -> master_secret / client_random */
    void *s3 = NULL;
    if (bpf_probe_read_user(&s3, sizeof(s3), (void *)(ssl + SSL_S3_OFFSET)) != 0)
        return 0;

    /* Read TLS version from s3 */
    __u16 version = 0;
    bpf_probe_read_user(&version, sizeof(version), (void *)(s3 + VERSION_OFFSET));

    /* Only capture TLS 1.2 (0x0303) for now */
    if (version != 0x0303)
        return 0;

    /* Read client_random (32 bytes) */
    __u8 client_random[TLS_CLIENT_RANDOM_SIZE];
    if (bpf_probe_read_user(&client_random, sizeof(client_random),
                           (void *)(s3 + CLIENT_RANDOM_OFFSET)) != 0)
        return 0;

    /* Check if client_random is all zeros (not yet generated) */
    int has_random = 0;
    for (int i = 0; i < TLS_CLIENT_RANDOM_SIZE; i++) {
        if (client_random[i] != 0) {
            has_random = 1;
            break;
        }
    }
    if (!has_random)
        return 0;

    /* Read master_secret (48 bytes) */
    __u8 master_secret[TLS_MASTER_SECRET_SIZE];
    if (bpf_probe_read_user(&master_secret, sizeof(master_secret),
                           (void *)(s3 + MASTER_KEY_OFFSET)) != 0)
        return 0;

    /* Check if master_secret is all zeros (not yet generated) */
    int has_secret = 0;
    for (int i = 0; i < TLS_MASTER_SECRET_SIZE; i++) {
        if (master_secret[i] != 0) {
            has_secret = 1;
            break;
        }
    }
    if (!has_secret)
        return 0;

    /* Submit master secret event */
    struct master_secret_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = pid_tgid >> 32;
    evt->tid = (__u32)pid_tgid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->type = EVENT_MASTER_SECRET;
    evt->version = version;
    evt->cipher_id = 0;
    evt->is_client = 1;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    __builtin_memcpy(evt->client_random, client_random, TLS_CLIENT_RANDOM_SIZE);
    __builtin_memcpy(evt->master_secret, master_secret, TLS_MASTER_SECRET_SIZE);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* --- SSL_read_ex probes --- */

SEC("uprobe")
int ssl_read_ex_entry(struct pt_regs *ctx)
{
    if (!check_target_pid())
        return 0;

    void *ssl = (void *)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    /* PARM3 is num (size_t) */
    void *readbytes_ptr = (void *)PT_REGS_PARM4(ctx);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args args = {
        .buf = (__u64)buf,
        .ssl_ptr = (__u64)ssl,
        .bytes_ptr = (__u64)readbytes_ptr,
    };
    bpf_map_update_elem(&ssl_read_ex_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int ssl_read_ex_return(struct pt_regs *ctx)
{
    if (!check_target_pid())
        return 0;
    int ret = (int)PT_REGS_RC(ctx);
    return process_ssl_ex_return(&ssl_read_ex_args, EVENT_SSL_READ, ret);
}
