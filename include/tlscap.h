/* include/tlscap.h - Shared data structures for BPF and user-space */
#ifndef TLSCAP_H
#define TLSCAP_H

#ifndef __BPF_PROGRAM__
#include <linux/types.h>
#endif

#define MAX_DATA_SIZE  16384
#define MAX_COMM_SIZE  16

enum event_type {
    EVENT_SSL_READ  = 0,
    EVENT_SSL_WRITE = 1,
};

struct tls_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp_ns;
    __u32 type;
    __u32 data_len;
    __u8  truncated;
    __u8  _pad[3];
    __u32 _pad2;
    __u64 ssl_ptr;
    char  comm[MAX_COMM_SIZE];
    char  data[MAX_DATA_SIZE];
};

struct ssl_args {
    __u64 buf;
    __u64 ssl_ptr;
    __u64 bytes_ptr;  /* For SSL_read_ex/SSL_write_ex: pointer to size_t output */
};

#endif /* TLSCAP_H */
