#ifndef __KANAWHA__CLK_H__
#define __KANAWHA__CLK_H__

#include <kanawha/time.h>

struct clk_dev;

int
clk_delay(duration_t duration);

// 0 -> No monotonic clock is available
// 1 -> clk_mono_* functions should work
int
clk_mono_valid(void);
duration_t
clk_mono_current(void);

// int
// clk_source_set(struct clk_dev *clk);
//
// struct clk_dev *
// clk_source_get(void);

#endif
