/* src/event_reader.c */
#include <stdio.h>
#include "event_reader.h"
#include "output.h"
#include "tlscap.h"

static unsigned long events_lost = 0;

static int event_handler(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    if (data_sz < sizeof(struct tls_event)) {
        events_lost++;
        return 0;
    }
    const struct tls_event *evt = data;
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
