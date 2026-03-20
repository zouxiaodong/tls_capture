/* src/ssl_detect.h */
#ifndef SSL_DETECT_H
#define SSL_DETECT_H

#include <sys/types.h>
#include <stddef.h>

/*
 * Detect libssl.so path.
 * Priority: user_path > /proc/pid/maps > ldconfig.
 * Returns 0 on success, -1 on failure.
 */
int ssl_detect(pid_t pid, const char *user_path,
               char *result, size_t result_size);

/* Parse a single /proc/pid/maps line for libssl.so path. */
int ssl_detect_parse_maps_line(const char *line,
                               char *path, size_t path_size);

/* Parse a single ldconfig -p output line for libssl.so path. */
int ssl_detect_parse_ldconfig_line(const char *line,
                                   char *path, size_t path_size);

#endif /* SSL_DETECT_H */
