#ifndef __KANAWHA__TASKLET_H__
#define __KANAWHA__TASKLET_H__

#include <kanawha/time.h>

struct tasklet;

typedef void(tasklet_f)(void *);

struct tasklet *
tasklet_create(tasklet_f *func, void *state);

int
tasklet_destroy(struct tasklet *tasklet);

int
tasklet_name(struct tasklet *task, const char *name);

// Ensure that the tasklet will run at least once
// in the future (unless it is destroyed before it can run)
//
// (If multiple calls are made to tasklet trigger before it,
//  actually runs then they will be coalesced into a single call)
//
int
tasklet_trigger(struct tasklet *tasklet);

/*
 * Like periodic_event(s) but run
 * in a thread context like tasklets
 */

struct periodic_tasklet;

struct periodic_tasklet *
tasklet_create_periodic(duration_t period, void *state, tasklet_f *func);

int
tasklet_destroy_periodic(struct periodic_tasklet *task);

#endif
