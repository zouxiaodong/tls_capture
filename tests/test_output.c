/* tests/test_output.c */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "output.h"
#include "tlscap.h"

static void test_is_printable_ascii(void)
{
    assert(output_is_printable("GET /index.html HTTP/1.1\r\n", 26) == 1);
}

static void test_is_printable_binary(void)
{
    char bin[] = {0x00, 0x01, 0x02, 0x03};
    assert(output_is_printable(bin, 4) == 0);
}

static void test_is_printable_empty(void)
{
    assert(output_is_printable("", 0) == 1);
}

static void test_format_timestamp_nonzero(void)
{
    output_init();
    char buf[32];
    output_format_timestamp(1000000000ULL, buf, sizeof(buf));
    assert(strlen(buf) >= 23);
    assert(buf[4] == '-');
    assert(buf[7] == '-');
    assert(buf[10] == ' ');
    assert(buf[13] == ':');
    assert(buf[16] == ':');
    assert(buf[19] == '.');
}

int main(void)
{
    test_is_printable_ascii();
    test_is_printable_binary();
    test_is_printable_empty();
    test_format_timestamp_nonzero();
    printf("output: all 4 tests passed\n");
    return 0;
}
