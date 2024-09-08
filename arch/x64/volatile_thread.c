
#include <kanawha/thread.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/scheduler.h>
#include <kanawha/string.h>
#include <kanawha/stdint.h>
#include <kanawha/init.h>
#include <kanawha/assert.h>

extern void x64_volatility_thread(void *in);

static int
x64_register_volatility_thread(void)
{
    int res;

    struct thread_state *volatile_thread =
        kmalloc(sizeof(struct thread_state));
    if(volatile_thread == NULL) {
        return -ENOMEM;
    }
    memset(volatile_thread, 0, sizeof(struct thread_state));

    res = thread_init(
            volatile_thread,
            x64_volatility_thread,
            NULL,
            0x0);
    if(res) {
        return res;
    }

    // TODO: Manage schedulers better instead
    //   of just grabbing the current one
    //   (processes do this too at the moment)
    struct scheduler *sched = current_sched();
    if(sched == NULL) {
        kfree(volatile_thread);
        return -EINVAL;
    }

    res = scheduler_add_thread(sched, volatile_thread);
    if(res) {
        kfree(volatile_thread);
        return res;
    }

    return 0;
}

declare_init_desc(late, x64_register_volatility_thread, "Starting x64 Volatility Debug Thread");

void
x64_volatility_thread_fail(
        const char *reg_str,
        uint64_t corrupt,
        uint64_t checksum)
{
    panic("x64 Thread Volatility Thread Detected a Corrupted Register! reg=%s, corrupt=%p, original=%p",
            reg_str, corrupt, checksum);
}
