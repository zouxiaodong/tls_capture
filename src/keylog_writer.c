/* src/keylog_writer.c - NSS keylog format writer for Wireshark decryption */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include "keylog_writer.h"
#include "tlscap.h"

static FILE *keylog_file = NULL;

static void bytes_to_hex(const uint8_t *src, size_t len, char *dst)
{
    for (size_t i = 0; i < len; i++) {
        sprintf(dst + i * 2, "%02x", src[i]);
    }
    dst[len * 2] = '\0';
}

int keylog_writer_init(const char *path)
{
    if (!path || path[0] == '\0') {
        return -1;
    }

    keylog_file = fopen(path, "a");
    if (!keylog_file) {
        fprintf(stderr, "Error: Cannot open keylog file %s: %s\n", path, strerror(errno));
        return -1;
    }

    fprintf(stderr, "Keylog output enabled: %s\n", path);
    return 0;
}

int keylog_writer_is_enabled(void)
{
    return keylog_file != NULL;
}

void keylog_writer_close(void)
{
    if (keylog_file) {
        fclose(keylog_file);
        keylog_file = NULL;
    }
}

int keylog_writer_write(const struct master_secret_event *evt)
{
    if (!keylog_file || !evt) {
        return 0;
    }

    /* Convert client_random and master_secret to hex */
    char client_random_hex[TLS_CLIENT_RANDOM_SIZE * 2 + 1];
    char master_secret_hex[TLS_MASTER_SECRET_SIZE * 2 + 1];

    bytes_to_hex(evt->client_random, TLS_CLIENT_RANDOM_SIZE, client_random_hex);
    bytes_to_hex(evt->master_secret, TLS_MASTER_SECRET_SIZE, master_secret_hex);

    /* NSS keylog format: CLIENT_RANDOM <hex> <hex> */
    fprintf(keylog_file, "CLIENT_RANDOM %s %s\n", client_random_hex, master_secret_hex);
    fflush(keylog_file);

    return 0;
}
