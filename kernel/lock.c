
#include <kanawha/lock.h>
#include <kanawha/scheduler.h>
#include <kanawha/thread.h>

void
thread_lock_failed_acquisition(thread_lock_t *lock)
{
    if(current_thread() != NULL)
    {
        soft_resched();
        thread_yield();
    }
}
