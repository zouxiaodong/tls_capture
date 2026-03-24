/* src/pcap_writer.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include "pcap_writer.h"
#include "tlscap.h"

/* PCAP global header (24 bytes) */
struct pcap_file_header {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

/* PCAP packet header (16 bytes) */
struct pcap_pkthdr {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

/* Ethernet header (14 bytes) */
struct ethernet_header {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t type;
};

/* IPv4 header (20 bytes) */
struct ip_header {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};

/* TCP header (20 bytes) */
struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};

#define PCAP_MAGIC          0xa1b2c3d4
#define ETHERNET_TYPE_IP   0x0800
#define IP_PROTOCOL_TCP    6

static FILE *pcap_file = NULL;
static int64_t mono_to_wall_offset_ns = 0;
static uint16_t packet_id = 0;

static uint16_t calc_ip_checksum(const void *data, int len)
{
    const uint16_t *ptr = data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len > 0)
        sum += *(const uint8_t *)ptr;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

int pcap_writer_init(const char *path)
{
    if (!path || path[0] == '\0') {
        return -1;
    }

    struct timespec mono, wall;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    clock_gettime(CLOCK_REALTIME, &wall);
    int64_t m = (int64_t)mono.tv_sec * 1000000000LL + mono.tv_nsec;
    int64_t w = (int64_t)wall.tv_sec * 1000000000LL + wall.tv_nsec;
    mono_to_wall_offset_ns = w - m;

    pcap_file = fopen(path, "wb");
    if (!pcap_file) {
        fprintf(stderr, "Error: Cannot open PCAP file %s: %s\n", path, strerror(errno));
        return -1;
    }

    struct pcap_file_header pfh = {
        .magic = PCAP_MAGIC,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1
    };

    if (fwrite(&pfh, sizeof(pfh), 1, pcap_file) != 1) {
        fprintf(stderr, "Error: Failed to write PCAP header\n");
        fclose(pcap_file);
        pcap_file = NULL;
        return -1;
    }

    fprintf(stderr, "PCAP output enabled: %s\n", path);
    return 0;
}

int pcap_writer_is_enabled(void)
{
    return pcap_file != NULL;
}

void pcap_writer_close(void)
{
    if (pcap_file) {
        fclose(pcap_file);
        pcap_file = NULL;
    }
}

int pcap_writer_write(const struct tls_event *evt)
{
    if (!pcap_file || !evt || evt->data_len == 0) {
        return 0;
    }

    int64_t wall_ns = (int64_t)evt->timestamp_ns + mono_to_wall_offset_ns;
    uint32_t ts_sec = (uint32_t)(wall_ns / 1000000000LL);
    uint32_t ts_usec = (uint32_t)((wall_ns % 1000000000LL) / 1000);

    uint16_t src_port = (uint16_t)(evt->pid & 0xFFFF);
    uint16_t dst_port = (uint16_t)((packet_id++ % 60000) + 1000);

    if (evt->type == EVENT_SSL_READ) {
        uint16_t tmp = src_port;
        src_port = dst_port;
        dst_port = tmp;
    }

    size_t eth_len = sizeof(struct ethernet_header);
    size_t ip_len = sizeof(struct ip_header);
    size_t tcp_len = sizeof(struct tcp_header);
    size_t payload_len = evt->data_len;
    if (payload_len >= MAX_DATA_SIZE)
        payload_len = MAX_DATA_SIZE - 1;
    size_t total_len = eth_len + ip_len + tcp_len + payload_len;

    uint8_t packet[eth_len + ip_len + tcp_len + payload_len];
    uint8_t *p = packet;

    struct ethernet_header *eth = (struct ethernet_header *)p;
    memset(eth->dst, 0x00, 6);
    memset(eth->src, 0x02, 6);
    eth->type = htons(ETHERNET_TYPE_IP);
    p += eth_len;

    struct ip_header *ip = (struct ip_header *)p;
    ip->version_ihl = (4 << 4) | 5;
    ip->tos = 0;
    ip->total_len = htons(ip_len + tcp_len + payload_len);
    ip->id = htons(packet_id);
    ip->flags_offset = 0;
    ip->ttl = 64;
    ip->protocol = IP_PROTOCOL_TCP;
    ip->checksum = 0;
    ip->src_addr = htonl(0x0a000001 + ((evt->pid & 0xFF) << 24));
    ip->dst_addr = htonl(0x0a000002 + ((evt->pid & 0xFF) << 24));
    ip->checksum = calc_ip_checksum(ip, sizeof(struct ip_header));
    p += ip_len;

    struct tcp_header *tcp = (struct tcp_header *)p;
    tcp->src_port = htons(src_port);
    tcp->dst_port = htons(dst_port);
    tcp->seq = htonl(1000 + evt->timestamp_ns % 1000000);
    tcp->ack = 0;
    tcp->data_offset = (5 << 4);
    tcp->flags = 0x18;
    tcp->window = htons(65535);
    tcp->checksum = 0;
    tcp->urgent = 0;
    p += tcp_len;

    memcpy(p, evt->data, payload_len);

    struct pcap_pkthdr pkthdr = {
        .ts_sec = ts_sec,
        .ts_usec = ts_usec,
        .incl_len = (uint32_t)total_len,
        .orig_len = (uint32_t)total_len
    };

    if (fwrite(&pkthdr, sizeof(pkthdr), 1, pcap_file) != 1) {
        return -1;
    }

    if (fwrite(packet, total_len, 1, pcap_file) != 1) {
        return -1;
    }

    return 0;
}
