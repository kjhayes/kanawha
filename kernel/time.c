
#include <kanawha/time.h>
#include <kanawha/periodic.h>
#include <kanawha/init.h>
#include <kanawha/errno.h>

static time_t system_timestamp = 0;
static struct periodic_event *tick_event = NULL;

time_t current_timestamp(void) {
    return system_timestamp;
}

static void
timestamp_tick(void *null) {
    system_timestamp += msec_to_duration(CONFIG_TIMESTAMP_RESOLUTION_MS);
}

static int 
start_timestamp_tick(void) {
    tick_event = create_periodic_event(
            msec_to_duration(CONFIG_TIMESTAMP_RESOLUTION_MS),
            NULL,
            timestamp_tick);
    if(tick_event == NULL) {
        return -EDEFER;
    }
    return 0;
}

declare_init_desc(late, start_timestamp_tick, "Starting Timestamp Tick Event");
