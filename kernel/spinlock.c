
#include <kanawha/spinlock.h>
#include <kanawha/init.h>

static int
enable_spinlock_tracking(void)
{
    __debug_spinlock_tracking_enabled = 1;
    return 0;
}
declare_init_desc(dynamic, enable_spinlock_tracking, "Enabling spinlock Thread Tracking");

