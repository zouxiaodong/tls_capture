/* src/pcap_writer.h */
#ifndef PCAP_WRITER_H
#define PCAP_WRITER_H

#include "tlscap.h"
#include <stdint.h>
#include <stddef.h>

/* Initialize PCAP writer with output file path.
 * Returns 0 on success, -1 on error.
 * If path is NULL or empty, PCAP writing is disabled. */
int pcap_writer_init(const char *path);

/* Write a TLS event to PCAP file.
 * Creates a pseudo-packet with IP/TCP headers for Wireshark compatibility.
 * Returns 0 on success, -1 on error. */
int pcap_writer_write(const struct tls_event *evt);

/* Flush and close PCAP file.
 * Call this before exiting. */
void pcap_writer_close(void);

/* Check if PCAP writing is enabled. */
int pcap_writer_is_enabled(void);

#endif /* PCAP_WRITER_H */
