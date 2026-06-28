#ifndef SYSGUARD_JSONL_WRITER_H
#define SYSGUARD_JSONL_WRITER_H

#include "event.h"
#include "alert.h"
#include <stdio.h>

FILE *jsonl_open(const char *path);
void  jsonl_write_event(FILE *fp, const struct sysguard_event *ev);
void  jsonl_write_alert(FILE *fp, const struct sysguard_event *ev, const struct sysguard_alert *alert);
void  jsonl_close(FILE *fp);

#endif
