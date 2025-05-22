
#include <kanawha/spinlock.h>
#include <kanawha/init.h>
#include <kanawha/cpu.h>
#include <kanawha/irq.h>

#ifdef CONFIG_DEBUG_SPINLOCK_TRACK_THREADS

int __debug_spinlock_tracking_enabled = 0;

static int
enable_spinlock_tracking(void)
{
    __debug_spinlock_tracking_enabled = 1;
    return 0;
}
declare_init_desc(dynamic, enable_spinlock_tracking, "Enabling spinlock Thread Tracking");
#endif

void
spinlock_failed_loop(
        spinlock_t *lock)
{
    if(!irqs_enabled() && total_num_cpus() <= 1) {
        panic("DEADLOCK: Single CPU is spinning on lock (%p) without interrupts enabled!\n",
                (void*)lock);
    }
}

