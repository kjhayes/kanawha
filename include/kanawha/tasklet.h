#ifndef __KANAWHA__TASKLET_H__
#define __KANAWHA__TASKLET_H__

struct tasklet;

typedef void(tasklet_f)(void *);

struct tasklet *
tasklet_create(
        tasklet_f *func,
        void *state);

int
tasklet_destroy(
        struct tasklet *tasklet);

// Ensure that the tasklet will run at least once
// in the future (unless it is destroyed before it can run)
//
// (If multiple calls are made to tasklet trigger before it,
//  actually runs then they will be coalesced into a single call)
// 
int
tasklet_trigger(
        struct tasklet *tasklet);

// Run this tasklet immediately in the current thread
int
tasklet_run(
        struct tasklet *tasklet);

#endif
