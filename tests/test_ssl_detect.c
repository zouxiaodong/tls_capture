/* tests/test_ssl_detect.c */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "ssl_detect.h"

static void test_parse_maps_line_found(void)
{
    char path[256];
    const char *line =
        "7f1234000000-7f1234100000 r-xp 00000000 08:01 12345 "
        "/usr/lib64/libssl.so.1.1\n";
    int ret = ssl_detect_parse_maps_line(line, path, sizeof(path));
    assert(ret == 0);
    assert(strcmp(path, "/usr/lib64/libssl.so.1.1") == 0);
}

static void test_parse_maps_line_not_found(void)
{
    char path[256];
    const char *line =
        "7f1234000000-7f1234100000 r-xp 00000000 08:01 12345 "
        "/usr/lib64/libc.so.6\n";
    int ret = ssl_detect_parse_maps_line(line, path, sizeof(path));
    assert(ret == -1);
}

static void test_parse_maps_line_no_path(void)
{
    char path[256];
    const char *line = "7f1234000000-7f1234100000 r-xp 00000000 08:01 12345\n";
    int ret = ssl_detect_parse_maps_line(line, path, sizeof(path));
    assert(ret == -1);
}

static void test_parse_ldconfig_line_found(void)
{
    char path[256];
    const char *line =
        "\tlibssl.so.1.1 (libc6,x86-64) => /usr/lib64/libssl.so.1.1\n";
    int ret = ssl_detect_parse_ldconfig_line(line, path, sizeof(path));
    assert(ret == 0);
    assert(strcmp(path, "/usr/lib64/libssl.so.1.1") == 0);
}

static void test_parse_ldconfig_line_not_found(void)
{
    char path[256];
    const char *line =
        "\tlibcrypto.so.1.1 (libc6,x86-64) => /usr/lib64/libcrypto.so.1.1\n";
    int ret = ssl_detect_parse_ldconfig_line(line, path, sizeof(path));
    assert(ret == -1);
}

static void test_ssl_detect_user_path_exists(void)
{
    char result[256];
    /* /proc/self/exe always exists on Linux */
    int ret = ssl_detect(0, "/proc/self/exe", result, sizeof(result));
    assert(ret == 0);
    assert(strcmp(result, "/proc/self/exe") == 0);
}

static void test_ssl_detect_user_path_not_found(void)
{
    char result[256];
    int ret = ssl_detect(0, "/nonexistent/libssl.so", result, sizeof(result));
    assert(ret == -1);
}

int main(void)
{
    test_parse_maps_line_found();
    test_parse_maps_line_not_found();
    test_parse_maps_line_no_path();
    test_parse_ldconfig_line_found();
    test_parse_ldconfig_line_not_found();
    test_ssl_detect_user_path_exists();
    test_ssl_detect_user_path_not_found();
    printf("ssl_detect: all 7 tests passed\n");
    return 0;
}
