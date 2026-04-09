
#include <kanawha/perf.h>

static void
perf_counter_display(
        struct perf_metric *metric,
        printk_f *printer)
{
    struct perf_counter *counter =
        container_of(metric, struct perf_counter, metric);
    (*printer)("count=%lu", (ul_t)counter->count);
}

static void
perf_timer_display(
        struct perf_metric *metric,
        printk_f *printer)
{
    struct perf_timer *timer =
        container_of(metric, struct perf_timer, metric);
    (*printer)("count=%lu, avg=%lu ms, min=%lu ms, max=%lu ms",
            (ul_t)timer->count,
            (ul_t)duration_to_msec(timer->avg),
            (ul_t)duration_to_msec(timer->min),
            (ul_t)duration_to_msec(timer->max)
            );
}

int perf_counter_init(struct perf_counter *metric)
{
    metric->count = 0;
    metric->metric.display = &perf_counter_display;
    return 0;
}
int perf_counter_register(struct perf_counter *counter, const char *name) {
    return register_perf_metric(&counter->metric, name);
}
int perf_counter_unregister(struct perf_counter *counter) {
    return unregister_perf_metric(&counter->metric);
}

int perf_timer_init(struct perf_timer *metric)
{
    metric->count = 0;
    metric->avg = 0;
    metric->max = 0;
    metric->min = -1ULL;

    metric->current_start = NULL_TIME;

    metric->metric.display = &perf_timer_display;
    return 0;
}
int perf_timer_register(struct perf_timer *timer, const char *name) {
    return register_perf_metric(&timer->metric, name);
}
int perf_timer_unregister(struct perf_timer *timer) {
    return unregister_perf_metric(&timer->metric);
}

void perf_counter_trigger(struct perf_counter *metric)
{
    metric->count++;
}
void perf_timer_start(struct perf_timer *metric)
{
    metric->current_start = current_timestamp();
}
void perf_timer_stop(struct perf_timer *metric)
{
    time_t start = metric->current_start;
    time_t end = current_timestamp();
    if(!times_are_sequential(start, end)) {
        metric->count++;
        return; // Ignore this data point's duration
    }
    duration_t dur = duration_between(start, end);

    duration_t sum = (metric->avg * metric->count) + dur;
    metric->count++;
    metric->avg = sum / metric->count;

    if(dur < metric->min) {
        metric->min = dur;
    }
    if(dur > metric->max) {
        metric->max = dur;
    }
}

static void
dump_perf_metrics_callback(
        struct perf_metric *metric,
        void *_printer)
{
    printk_f *printer = _printer;
    DEBUG_ASSERT(KERNEL_ADDR(printer));
    DEBUG_ASSERT(KERNEL_ADDR(metric));
    DEBUG_ASSERT(KERNEL_ADDR(metric->display));
    printer("%s - ", perf_metric_get_name(metric));
    (*metric->display)(metric, printer);
    printer("\n");
}

void dump_perf_metrics(printk_f *printer)
{
    for_each_perf_metric(
            dump_perf_metrics_callback,
            printer);
}

DEFINE_REGISTRY(
        perf_metric,
        registry_node,
        REGISTRY_NO_INIT_FUNCTION,
        REGISTRY_NO_DEINIT_FUNCTION);

#ifdef CONFIG_DEBUG_DUMP_PERF_METRICS_PERIODICALLY
#include <kanawha/event.h>
static struct periodic_event *debug_dump_perf_metrics_event = NULL;
static void
debug_dump_perf_metrics_periodically(void *state)
{
    dump_perf_metrics(do_printk);
}
static int
init_debug_dump_perf_metrics_periodically(void)
{
    debug_dump_perf_metrics_event = create_periodic_event(
        sec_to_duration(CONFIG_DEBUG_DUMP_PERF_METRICS_PERIODICALLY_PERIOD),
        NULL,
        debug_dump_perf_metrics_periodically);
    if(debug_dump_perf_metrics_event == NULL)
    {
        return -EINVAL;
    }
    return 0;
}
declare_init(launch, init_debug_dump_perf_metrics_periodically);
#endif

