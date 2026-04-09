#ifndef __KANAWHA__APIC_TIMER_H__
#define __KANAWHA__APIC_TIMER_H__

#include <kanawha/dev/clk.h>
#include <kanawha/dev/timer.h>

struct x64_cpu;

struct lapic_timer
{
    struct timer_dev timer_dev;
    struct clk_dev clk_dev;

    char *name;

    freq_t freq;
    int periodic;

    alarm_f *alarm_func;
};

int
apic_timer_init_current(void);

int
register_cpu_lapic_timer(struct x64_cpu *cpu);

#endif
