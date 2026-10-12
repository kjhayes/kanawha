#ifndef __LASSIE_JSON_H__
#define __LASSIE_JSON_H__

#include <lassie/lassie.h>
#include <stdio.h>

struct lassie *
lassie_json_read(FILE *file);

#define LASSIE_JSON_WRITE_COMPACT (1UL<<0)
#define LASSIE_JSON_WRITE_NO_INITIAL_INDENT (1UL<<1)
int
lassie_json_write(
        FILE *file,
        struct lassie *value,
        unsigned long flags,
        int depth);

#endif
