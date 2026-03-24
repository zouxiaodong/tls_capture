/* src/event_reader.c */
#include <stdio.h>
#include "event_reader.h"
#include "output.h"
#include "keylog_writer.h"
#include "tlscap.h"

static unsigned long events_lost = 0;

static int event_handler(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    fprintf(stderr, "[DEBUG] event_handler called with data_sz=%zu\n", data_sz);

    if (data_sz >= sizeof(struct master_secret_event)) {
        const struct master_secret_event *ms_evt = data;
        if (ms_evt->type == EVENT_MASTER_SECRET) {
            fprintf(stderr, "[DEBUG] Processing master secret event: pid=%u\n", ms_evt->pid);
            if (keylog_writer_is_enabled()) {
                keylog_writer_write(ms_evt);
            }
            return 0;
        }
    }

    if (data_sz < sizeof(struct tls_event)) {
        fprintf(stderr, "[DEBUG] Event too small: %zu < %zu\n", data_sz, sizeof(struct tls_event));
        events_lost++;
        return 0;
    }
    const struct tls_event *evt = data;
    fprintf(stderr, "[DEBUG] Processing event: type=%d, data_len=%u\n", evt->type, evt->data_len);
    output_event(evt);
    return 0;
}

struct ring_buffer *event_reader_create(int map_fd)
{
    return ring_buffer__new(map_fd, event_handler, NULL, NULL);
}

int event_reader_poll(struct ring_buffer *rb, int timeout_ms)
{
    return ring_buffer__poll(rb, timeout_ms);
}

void event_reader_destroy(struct ring_buffer *rb)
{
    ring_buffer__free(rb);
}

unsigned long event_reader_get_lost(void)
{
    unsigned long lost = events_lost;
    events_lost = 0;
    return lost;
}
