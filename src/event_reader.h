/* src/event_reader.h */
#ifndef EVENT_READER_H
#define EVENT_READER_H

#include <bpf/libbpf.h>

/* Create a ring buffer reader for the given map fd. */
struct ring_buffer *event_reader_create(int map_fd);

/* Poll the ring buffer. Returns number of events consumed, or negative on error. */
int event_reader_poll(struct ring_buffer *rb, int timeout_ms);

/* Destroy the ring buffer reader. */
void event_reader_destroy(struct ring_buffer *rb);

/* Get number of events lost since last check, then reset counter. */
unsigned long event_reader_get_lost(void);

#endif /* EVENT_READER_H */
