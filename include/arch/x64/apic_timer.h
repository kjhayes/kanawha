#ifndef __KANAWHA__APIC_TIMER_H__
#define __KANAWHA__APIC_TIMER_H__

#include <kanawha/device.h>
#include <kanawha/timer_dev.h>

struct x64_cpu;

struct lapic_timer
{
    struct device device;
    struct timer_dev timer_dev;

    freq_t freq;
    int periodic;

    alarm_f *alarm_func;
};

int
apic_timer_init_current(void);

int
register_cpu_lapic_timer(struct x64_cpu *cpu);

#endif
