#ifndef __KANAWHA__CLK_DEV_H__
#define __KANAWHA__CLK_DEV_H__

#include <kanawha/time.h>
#include <kanawha/ops.h>

struct clk_dev;
struct clk_driver;

#define CLK_DEV_FREQ_SIG(RET,ARG)\
RET(freq_t)

#define CLK_DEV_MONO_CYCLES_SIG(RET,ARG)\
RET(cycles_t)

#define CLK_DEV_OP_LIST(OP, ...)\
OP(freq, CLK_DEV_FREQ_SIG, ##__VA_ARGS__)\
OP(mono_cycles, CLK_DEV_MONO_CYCLES_SIG, ##__VA_ARGS__)

struct clk_driver {
DECLARE_OP_LIST_PTRS(CLK_DEV_OP_LIST, struct clk_dev *)
};

struct clk_dev {
    struct clk_driver *driver;
};

DEFINE_OP_LIST_WRAPPERS(
        CLK_DEV_OP_LIST,
        static inline,
        /* No Prefix */,
        clk_dev,
        ->driver->,
        SELF_ACCESSOR)

#undef CLK_DEV_FREQ_SIG
#undef CLK_DEV_OP_LIST

#endif
