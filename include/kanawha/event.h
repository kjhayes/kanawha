#ifndef __KANAWHA__EVENT_H__
#define __KANAWHA__EVENT_H__

#include <kanawha/time.h>

typedef void(periodic_callback_f)(void *state);

struct periodic_event;
struct periodic_task;

// May run in an interrupt context
struct periodic_event *
create_periodic_event(duration_t period,
                      void *state,
                      periodic_callback_f *callback);

int
destroy_periodic_event(struct periodic_event *event);

#endif
