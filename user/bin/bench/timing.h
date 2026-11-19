#ifndef __BENCH__TIMING_H__
#define __BENCH__TIMING_H__

#include <time.h>
#include <stdio.h>

typedef struct elapse {
    clock_t start;
    clock_t end;
} elapse_t;

static inline void
elapse_begin(elapse_t *e)
{
    e->start = clock();
}
static inline void
elapse_end(elapse_t *e)
{
    e->end = clock();
}

static inline unsigned long
elapsed_msec(elapse_t *e)
{
    clock_t delta_clk = e->end - e->start;
    return (1000*delta_clk) / CLOCKS_PER_SEC;
}

static inline void
print_elapsed_sec(FILE *f, elapse_t *e)
{
    clock_t delta_clk = e->end - e->start;
    unsigned long msec = delta_clk / (CLOCKS_PER_SEC/1000);
    unsigned long sec = msec / 1000;
    unsigned int d_dsec = (msec / 100) % 10;
    unsigned int d_csec = (msec / 10) % 10;
    unsigned int d_msec = (msec) % 10;

    fprintf(f, "%lu.%u%u%u",
            sec, d_dsec, d_csec, d_msec);
}

#endif
