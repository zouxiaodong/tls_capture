/* src/ssl_detect.c */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "ssl_detect.h"

#define MAX_LINE 512

int ssl_detect_parse_maps_line(const char *line,
                               char *path, size_t path_size)
{
    if (!strstr(line, "libssl.so"))
        return -1;

    const char *p = strchr(line, '/');
    if (!p)
        return -1;

    size_t len = strlen(p);
    while (len > 0 && (p[len - 1] == '\n' || p[len - 1] == ' '))
        len--;

    if (len == 0 || len >= path_size)
        return -1;

    memcpy(path, p, len);
    path[len] = '\0';
    return 0;
}

int ssl_detect_parse_ldconfig_line(const char *line,
                                   char *path, size_t path_size)
{
    if (!strstr(line, "libssl.so"))
        return -1;

    const char *arrow = strstr(line, "=> ");
    if (!arrow)
        return -1;

    const char *p = arrow + 3;
    while (*p == ' ')
        p++;

    size_t len = strlen(p);
    while (len > 0 && (p[len - 1] == '\n' || p[len - 1] == ' '))
        len--;

    if (len == 0 || len >= path_size)
        return -1;

    memcpy(path, p, len);
    path[len] = '\0';
    return 0;
}

static int ssl_detect_from_pid(pid_t pid, char *path, size_t path_size)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *f = fopen(maps_path, "r");
    if (!f)
        return -1;

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        if (ssl_detect_parse_maps_line(line, path, path_size) == 0) {
            fclose(f);
            return 0;
        }
    }

    fclose(f);
    return -1;
}

static int ssl_detect_from_ldconfig(char *path, size_t path_size)
{
    FILE *f = popen("ldconfig -p 2>/dev/null", "r");
    if (!f)
        return -1;

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        if (ssl_detect_parse_ldconfig_line(line, path, path_size) == 0) {
            pclose(f);
            return 0;
        }
    }

    pclose(f);
    return -1;
}

int ssl_detect(pid_t pid, const char *user_path,
               char *result, size_t result_size)
{
    if (user_path && user_path[0]) {
        if (access(user_path, F_OK) != 0)
            return -1;
        snprintf(result, result_size, "%s", user_path);
        return 0;
    }

    if (pid > 0 && ssl_detect_from_pid(pid, result, result_size) == 0)
        return 0;

    return ssl_detect_from_ldconfig(result, result_size);
}
