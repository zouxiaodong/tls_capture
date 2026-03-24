/* src/keylog_writer.h */
#ifndef KEYLOG_WRITER_H
#define KEYLOG_WRITER_H

#include "tlscap.h"
#include <stdint.h>

int keylog_writer_init(const char *path);
int keylog_writer_write(const struct master_secret_event *evt);
void keylog_writer_close(void);
int keylog_writer_is_enabled(void);

#endif
