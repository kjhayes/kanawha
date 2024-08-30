#ifndef __KANAWHA__CLK_H__
#define __KANAWHA__CLK_H__

#include <kanawha/time.h>
#include <kanawha/clk_dev.h>

int clk_delay(duration_t duration);
duration_t clk_mono_current(void);

int
clk_source_set(struct clk_dev *clk);

struct clk_dev *
clk_source_get(void);

#endif
