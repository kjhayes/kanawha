#ifndef __KANAWHA__INIT_H__
#define __KANAWHA__INIT_H__

// STAGE_NAME, BSP_ONLY
#define XFOR_INIT_STAGE(X)\
    X(boot)\
    X(static)\
    X(mem_flags)\
    X(post_mem_flags)\
    X(page_alloc)\
    X(vmem)\
    X(post_vmem)\
    X(kmalloc)\
    X(dynamic)\
    X(topo)\
    X(post_topo)\
    X(smp_bringup)\
    X(smp)\
    X(fs)\
    X(platform)\
    X(bus)\
    X(early_device)\
    X(device)\
    X(late)\
    X(launch)

/*
 * init_stages Overview
 */

// boot - extremely early, architecture specific what can go here
// static - static data structure initialization, basic string functions should work
// mem_flags - memory discovery / mem_flags population
// post_mem_flags - memory reservation
// page_alloc - page allocator initialization
// vmem - virtual memory map initialization
// post_vmem - virtual memory map enabling
// kmalloc - dynamic memory allocator initialization
// dynamic - first stage with kmalloc/kfree family of functions
// topo - system topology discovery
// post_topo - total_num_cpus and percpu_ptr_specific working on BSP
// smp_bringup - bringing up the AP's
// smp - first smp phase (xcalls should work)
// fs - filesystem registration
// platform - non-bus based devices
// bus - bus discovery/probing
// early_device - early device driver initialization
// device - device drivers
// late - generic "late" init functions, currently just for loading the initrd and additional modules found there
// launch - launching the root process

#ifndef __LINKER__

#include <kanawha/stdint.h>
#include <kanawha/stddef.h>

typedef int(init_f)(void);

struct init_stage_event {
    init_f *func;
    const char *desc_name;
};


// Declare the handle_init_stage_* function for each init stage
#define DECLARE_INIT_STAGE_HANDLER(STAGE, ...)\
int handle_init_stage__ ## STAGE(void);

XFOR_INIT_STAGE(DECLARE_INIT_STAGE_HANDLER)

#define declare_init(STAGE, FUNC)\
        declare_init_desc(STAGE, FUNC, NULL)

#define declare_init_desc(STAGE, FUNC, DESC)\
    __attribute__((section(".kinit." #STAGE ".init"))) \
    __attribute__((used))\
    static struct init_stage_event __ ## FUNC ## _init_ ## STAGE ##_event = {\
        .func = FUNC,\
        .desc_name = DESC,\
    }

int
handle_init_stage_generic(
        const char *stage_name, 
        size_t num_events, 
        struct init_stage_event events[num_events]);

#endif // __LINKER__
#endif
