
#include <kanawha/clk.h>
#include <kanawha/errno.h>
#include <kanawha/event.h>
#include <kanawha/init.h>
#include <kanawha/time.h>

static duration_t system_timestamp = 0;
static struct periodic_event *tick_event = NULL;

time_t
current_timestamp(void)
{
    duration_t clk = 0;
    time_t time = {
        .clk_mono = clk,
        .tick = system_timestamp,
    };
    return time;
}

static void
timestamp_tick(void *null)
{
    system_timestamp += msec_to_duration(CONFIG_TIMESTAMP_RESOLUTION_MS);
}

static int
start_timestamp_tick(void)
{
    tick_event =
        create_periodic_event(msec_to_duration(CONFIG_TIMESTAMP_RESOLUTION_MS),
                              NULL,
                              timestamp_tick);
    if(tick_event == NULL)
    {
        return -EDEFER;
    }
    return 0;
}

declare_init_desc(late, start_timestamp_tick, "Starting Timestamp Tick Event");
