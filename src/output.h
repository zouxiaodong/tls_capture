/* src/output.h */
#ifndef OUTPUT_H
#define OUTPUT_H

#include "tlscap.h"
#include <stdint.h>
#include <stddef.h>

/* Call once at startup to compute monotonic-to-wallclock offset. */
void output_init(void);

/* Print a TLS event to stdout with separator and metadata. */
void output_event(const struct tls_event *evt);

/* Format monotonic timestamp to wall-clock string.
 * Exposed for testing. Buffer must be >= 32 bytes. */
void output_format_timestamp(uint64_t timestamp_ns,
                             char *buf, size_t size);

/* Check if data is printable ASCII text.
 * Exposed for testing. */
int output_is_printable(const char *data, uint32_t len);

#endif /* OUTPUT_H */
