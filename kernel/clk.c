
#include <kanawha/clk.h>
#include <kanawha/time.h>
#include <kanawha/dev/clk.h>
#include <kanawha/common.h>
#include <kanawha/errno.h>

DEFINE_LOCAL_THREAD_LOCK(clk_source_lock);
static struct clk_dev *clk_source = NULL;

int
clk_delay(duration_t duration)
{
    if(clk_source == NULL) {
        return -ENODEV;
    }
    duration_t initial = clk_mono_current();

    duration_t prev = initial;
    while(duration > 0) {

        duration_t cur = clk_mono_current();
        while(cur == prev) {
            pause();
            if((volatile struct clk_dev *)clk_source == NULL) {
                return -ENODEV;
            }
            cur = clk_mono_current();
        }

        if(cur < prev) {
            // Overflow (Skip a loop)
//            wprintk("clk_delay overflow (initial=0x%llx, cur=0x%llx, prev=0x%llx)\n",
//                    (ull_t)initial, (ull_t)cur, (ull_t)prev);
            prev = cur;
            continue;
        }

        duration_t elapsed = cur - prev;
        if(duration <= elapsed) {
            duration = 0;
        } else {
            duration -= elapsed;
            prev = cur;
        }
    }
    return 0;
}

int clk_mono_valid(void) {
    return clk_source != NULL;
}
duration_t clk_mono_current(void)
{
    clk_source_lock_acquire();
    if(clk_source == NULL) {
        return 0;
    }

    size_t cur_count = clk_dev_mono_cycles(clk_source);
    duration_t dur = freq_cycles_to_duration(clk_dev_freq(clk_source), cur_count);
    clk_source_lock_release();
    return dur;
}

static void
clk_mono_on_clk_dev_register(
        struct clk_dev *dev
        )
{
    // Make sure this isn't a CPU local clk device,
    // which would make a VERY poor if not incorrect
    // clock source
    if(dev->flags & CLK_DEV_FLAG_PERCPU) {
        return;
    }

    clk_source_lock_acquire();
    freq_t new_freq = clk_dev_freq(dev);
    if(clk_source == NULL || (new_freq > clk_dev_freq(clk_source))) {
        if(clk_source == NULL) {
            printk("Setting clk_mono to be \"%s\"\n",
                    clk_dev_get_name(dev));
        } else {
            printk("Replacing current clock source with \"%s\" due to higher frequency\n",
                    clk_dev_get_name(dev));
        }
        clk_source = dev;
    }
    clk_source_lock_release();
}
static void
clk_mono_on_clk_dev_unregister(
        struct clk_dev *dev
        )
{
    clk_source_lock_acquire();
    if(clk_source == dev) {
        clk_source = NULL;
        eprintk("Lost primary clk_dev for kernel time-keeping! (%s)\n",
                clk_dev_get_name(dev));
    }
    clk_source_lock_release();
}
LOCAL_REGISTRY_HOOK(
        clk_mono_clk_dev_hook,
        clk_dev,
        clk_mono_on_clk_dev_register,
        clk_mono_on_clk_dev_unregister)

//int
//clk_source_set(struct clk_dev *clk)
//{
//    clk_source = clk;
//    return 0;
//}
//
//struct clk_dev *
//clk_source_get(void)
//{
//    return clk_source;
//}

