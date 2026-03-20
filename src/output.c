/* src/output.c */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <stdint.h>
#include "output.h"

static int64_t mono_to_wall_offset_ns = 0;

void output_init(void)
{
    struct timespec mono, wall;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    clock_gettime(CLOCK_REALTIME, &wall);
    int64_t m = (int64_t)mono.tv_sec * 1000000000LL + mono.tv_nsec;
    int64_t w = (int64_t)wall.tv_sec * 1000000000LL + wall.tv_nsec;
    mono_to_wall_offset_ns = w - m;
}

void output_format_timestamp(uint64_t timestamp_ns,
                             char *buf, size_t size)
{
    int64_t wall_ns = (int64_t)timestamp_ns + mono_to_wall_offset_ns;
    time_t sec = (time_t)(wall_ns / 1000000000LL);
    long ms = (wall_ns % 1000000000LL) / 1000000;

    struct tm tm;
    localtime_r(&sec, &tm);
    snprintf(buf, size, "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
}

int output_is_printable(const char *data, uint32_t len)
{
    uint32_t check_len = len < 128 ? len : 128;
    for (uint32_t i = 0; i < check_len; i++) {
        unsigned char c = (unsigned char)data[i];
        if (!isprint(c) && !isspace(c))
            return 0;
    }
    return 1;
}

static void print_hex_dump(const char *data, uint32_t len)
{
    for (uint32_t i = 0; i < len; i += 16) {
        printf("  %04x  ", i);
        for (uint32_t j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", (unsigned char)data[i + j]);
            else
                printf("   ");
            if (j == 7)
                printf(" ");
        }
        printf(" |");
        for (uint32_t j = 0; j < 16 && i + j < len; j++) {
            unsigned char c = (unsigned char)data[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("|\n");
    }
}

void output_event(const struct tls_event *evt)
{
    const char *dir = (evt->type == EVENT_SSL_READ)
                      ? "READ (响应)"
                      : "WRITE (请求)";

    char ts[32];
    output_format_timestamp(evt->timestamp_ns, ts, sizeof(ts));

    printf("──── %s ──── %s[%u] PID:%u TID:%u ──── %s ────",
           dir, evt->comm, evt->pid, evt->pid, evt->tid, ts);

    if (evt->truncated)
        printf(" [TRUNCATED]");
    printf("\n");

    uint32_t print_len = evt->data_len;
    if (print_len >= MAX_DATA_SIZE)
        print_len = MAX_DATA_SIZE - 1;

    if (print_len == 0) {
        printf("  (empty)\n\n");
        return;
    }

    if (output_is_printable(evt->data, print_len)) {
        fwrite(evt->data, 1, print_len, stdout);
        printf("\n\n");
    } else {
        print_hex_dump(evt->data, print_len);
        printf("\n");
    }
}
