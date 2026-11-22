
#include <kanawha/pwait.h>
#include <kanawha/waitqueue.h>
#include <kanawha/pcache.h>
#include <kanawha/init.h>

// Trivial Implementation of "pwait" for now

static struct waitqueue pwaitqueue;

static int
pwait_init(void)
{
    waitqueue_init(&pwaitqueue);
    waitqueue_name(&pwaitqueue, "pwait");
    return 0;
}
declare_init(sched, pwait_init);

int
pwait_on(void __phys *addr)
{
    int res;
    res = wait_on(&pwaitqueue);
    return res;
}
int
pwake_all(void __phys *addr)
{
    int res;
    res = wake_all(&pwaitqueue);
    if(res) {
        return res;
    }
    return 0;
}
int
pwake_single(void __phys *addr)
{
    int res;
    res = wake_all(&pwaitqueue);
    if(res) {
        return res;
    }
    return 0;
}

