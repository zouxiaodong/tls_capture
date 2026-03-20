// SPDX-License-Identifier: GPL-2.0
// src/bpf/tlscap.bpf.c - eBPF probes for SSL_read/SSL_write

#include <linux/bpf.h>
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
    void *map, __u32 evt_type, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args *args = bpf_map_lookup_elem(map, &pid_tgid);
    if (!args)
        return 0;

    struct ssl_args saved = *args;
    bpf_map_delete_elem(map, &pid_tgid);

    if (ret <= 0)
        return 0;

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

    __u32 len = (__u32)ret;
    evt->data_len = len;
    if (len >= MAX_DATA_SIZE) {
        len = MAX_DATA_SIZE - 1;
        evt->truncated = 1;
    }

    int read_ret = bpf_probe_read_user(evt->data,
                        len & (MAX_DATA_SIZE - 1),
                        (void *)saved.buf);
    if (read_ret != 0)
        evt->data_len = 0;

    evt->data[len & (MAX_DATA_SIZE - 1)] = '\0';

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* --- SSL_write probes --- */

SEC("uprobe")
int BPF_UPROBE(ssl_write_entry, void *ssl, const void *buf, int num)
{
    if (!check_target_pid())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args args = {
        .buf = (__u64)buf,
        .ssl_ptr = (__u64)ssl,
    };
    bpf_map_update_elem(&ssl_write_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(ssl_write_return, int ret)
{
    if (!check_target_pid())
        return 0;
    return process_ssl_return(&ssl_write_args, EVENT_SSL_WRITE, ret);
}

/* --- SSL_read probes --- */

SEC("uprobe")
int BPF_UPROBE(ssl_read_entry, void *ssl, void *buf, int num)
{
    if (!check_target_pid())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args args = {
        .buf = (__u64)buf,
        .ssl_ptr = (__u64)ssl,
    };
    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(ssl_read_return, int ret)
{
    if (!check_target_pid())
        return 0;
    return process_ssl_return(&ssl_read_args, EVENT_SSL_READ, ret);
}
