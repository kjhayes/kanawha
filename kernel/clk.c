
#include <kanawha/clk.h>
#include <kanawha/time.h>
#include <kanawha/clk_dev.h>
#include <kanawha/common.h>

static struct clk_dev *clk_source = NULL;

int
clk_delay(duration_t duration)
{
    if(clk_source_get() == NULL) {
        return -ENODEV;
    }


    duration_t initial = clk_mono_current();

    duration_t prev = initial;
    while(duration > 0) {

        duration_t cur = clk_mono_current();
        while(cur == prev) {
            pause();
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

duration_t clk_mono_current(void)
{
    if(clk_source == NULL) {
        return 0;
    }

    size_t cur_count = clk_dev_mono_cycles(clk_source);
    return freq_cycles_to_duration(clk_dev_freq(clk_source), cur_count);
}

int
clk_source_set(struct clk_dev *clk)
{
    clk_source = clk;
    return 0;
}

struct clk_dev *
clk_source_get(void)
{
    return clk_source;
}

