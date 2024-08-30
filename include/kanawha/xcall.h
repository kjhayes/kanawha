#ifndef __KANAWHA__XCALL_H__
#define __KANAWHA__XCALL_H__

#include <kanawha/cpu.h>

typedef void(xcall_f)(void*);

int xcall_queue(cpu_id_t cpu, xcall_f *func, void *arg);
int xcall_notify(cpu_id_t cpu);

static inline
int xcall_run(cpu_id_t cpu, xcall_f *func, void *arg)
{
    int res;
    res = xcall_queue(cpu, func, arg);
    if(res) {return res;}
    res = xcall_notify(cpu);
    if(res) {return res;}
    return 0;
}

static inline
int xcall_broadcast(xcall_f *func, void *arg)
{
    int res = 0;
    for(cpu_id_t cpu = 0; cpu < total_num_cpus(); cpu++) {
        res = xcall_run(cpu, func, arg); 
        if(res) {
            eprintk("xcall_broadcast: failed to run on CPU %ld\n", (sl_t)cpu);
            continue;
        }
    }
    return res;
}

// Give the X-Call Subsystem a specific IPI which can be
// used for a CPU's xcall handler
// (This does not mean that the xcall subsystem will use
//  this specific handler)
int
xcall_provide_ipi_irq(cpu_id_t cpu, irq_t ipi_irq);

#endif
