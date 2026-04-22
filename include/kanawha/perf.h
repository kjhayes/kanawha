#ifndef __KANAWHA__PERF_H__
#define __KANAWHA__PERF_H__

#include <kanawha/printk.h>
#include <kanawha/registry.h>
#include <kanawha/stree.h>

struct perf_metric
{
    struct registry_node registry_node;
    void (*display)(struct perf_metric *metric, printk_f *printer);
};

struct perf_counter
{
    struct perf_metric metric;
    unsigned long count;
};

struct perf_timer
{
    struct perf_metric metric;

    unsigned long count;
    duration_t avg;
    duration_t max;
    duration_t min;

    time_t current_start;
};

int
perf_counter_init(struct perf_counter *metric);
int
perf_counter_register(struct perf_counter *metric, const char *name);
int
perf_counter_unregister(struct perf_counter *metric);

int
perf_timer_init(struct perf_timer *metric);
int
perf_timer_register(struct perf_timer *metric, const char *name);
int
perf_timer_unregister(struct perf_timer *metric);

void
perf_counter_trigger(struct perf_counter *metric);
void
perf_timer_start(struct perf_timer *metric);
void
perf_timer_stop(struct perf_timer *metric);

DECLARE_REGISTRY(perf_metric);

void
dump_perf_metrics(printk_f *printer);

#define DECLARE_LOCAL_PERF_COUNTER(_name)                                      \
    static struct perf_counter _name;                                          \
    static int static_init_perf_counter_##_name(void)                          \
    {                                                                          \
        return perf_counter_init(&_name);                                      \
    }                                                                          \
    declare_init(static, static_init_perf_counter_##_name);                    \
    static int dynamic_init_perf_counter_##_name(void)                         \
    {                                                                          \
        return perf_counter_register(&_name, #_name);                          \
    }                                                                          \
    declare_init(dynamic, dynamic_init_perf_counter_##_name);

#define DECLARE_LOCAL_PERF_TIMER(_name)                                        \
    static struct perf_timer _name;                                            \
    static int static_init_perf_timer_##_name(void)                            \
    {                                                                          \
        return perf_timer_init(&_name);                                        \
    }                                                                          \
    declare_init(static, static_init_perf_timer_##_name);                      \
    static int dynamic_init_perf_timer_##_name(void)                           \
    {                                                                          \
        return perf_timer_register(&_name, #_name);                            \
    }                                                                          \
    declare_init(dynamic, dynamic_init_perf_timer_##_name);

#endif
