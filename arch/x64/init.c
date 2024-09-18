
#include <kanawha/printk.h>
#include <kanawha/init.h>
#include <kanawha/errno.h>
#include <kanawha/percpu.h>
#include <kanawha/vmem.h>
#include <kanawha/thread.h>
#include <kanawha/device.h>
#include <kanawha/irq_domain.h>
#include <kanawha/clk.h>
#include <kanawha/usermode.h>

#include <arch/x64/fpu.h>
#include <arch/x64/gdt.h>
#include <arch/x64/idt.h>
#include <arch/x64/msr.h>
#include <arch/x64/smp.h>
#include <arch/x64/lapic.h>
#include <arch/x64/apic_timer.h>

extern int x64_boot_stack_base[];

void *x64_boot_bsp_init(void);
void x64_bsp_init(void);
void x64_init(void*);

// Physical Stack
void * x64_boot_bsp_init(void) 
{
    int res;

    x64_fpu_init_bsp();
    x64_init_gdt_bsp();
    x64_init_idt_bsp();

    printk_early_init();

    // boot Init Stages
    res = handle_init_stage__boot();
    if(res) {
        panic("Failed to handle init stage \"boot\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__static();
    if(res) {
        panic("Failed to handle init stage \"static\"! err=%s", errnostr(res));
    }

    return (void*)__va((uintptr_t)x64_boot_stack_base);
}

// Virtual Stack
void x64_bsp_init(void) {
    int res;

    printk("Initializing Kanawha Kernel...\n");

    // mem_flags Init Stages
    res = handle_init_stage__mem_flags();
    if(res) {
        panic("Failed to handle init stage \"mem_flags\"! err=%s", errnostr(res));
    }
    res = handle_init_stage__post_mem_flags();
    if(res) {
        panic("Failed to handle init stage \"post_mem_flags\"! err=%s", errnostr(res));
    }

    // alloc Init Stages
    res = handle_init_stage__page_alloc();
    if(res) {
        panic("Failed to handle init stage \"page_alloc\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__vmem();
    if(res) {
        panic("Failed to handle init stage \"vmem\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__post_vmem();
    if(res) {
        panic("Failed to handle init stage \"post_vmem\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__kmalloc();
    if(res) {
        panic("Failed to handle init stage \"kmalloc\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__dynamic();
    if(res) {
        panic("Failed to handle init stage \"dynamic\"! err=%s", errnostr(res));
    }

    printk("Starting threading on CPU (%ld)\n",
            (long)current_cpu_id());

    cpu_start_threading(x64_init, NULL);
    
    panic("x64_boot_init failed to start threading!\n");
}

void x64_init(void *in)
{
    int res;

    printk("Started threading on CPU (%ld)\n",
            (long)current_cpu_id());

    res = handle_init_stage__topo();
    if(res) {
        panic("Failed to handle init stage \"topo\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__post_topo();
    if(res) {
        panic("Failed to handle init stage \"post_topo\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__smp_bringup();
    if(res) {
        panic("Failed to handle init stage \"smp_bringup\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__smp();
    if(res) {
        panic("Failed to handle init stage \"smp\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__fs();
    if(res) {
        panic("Failed to handle init stage \"fs\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__platform();
    if(res) {
        panic("Failed to handle init stage \"platform\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__bus();
    if(res) {
        panic("Failed to handle init stage \"bus\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__early_device();
    if(res) {
        panic("Failed to handle init stage \"early_device\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__device();
    if(res) {
        panic("Failed to handle init stage \"device\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__late();
    if(res) {
        panic("Failed to handle init stage \"late\"! err=%s", errnostr(res));
    }

    res = handle_init_stage__launch();
    if(res) {
        panic("Failed to handle init stage \"launch\"! err=%s", errnostr(res));
    }

    //dump_device_hierarchy(printk);
    //dump_irq_descs(printk);
    //dump_threads(printk);

    printk("CPU (%ld) init thread is idling\n", (sl_t)current_cpu_id());
    idle_loop();

    panic("Returned from idle loop on CPU (%ld)!\n", (sl_t)current_cpu_id());
}

void x64_ap_init(void*);

__attribute__((noreturn))
void x64_boot_ap_init(void) 
{
    int res;

    cpu_id_t self = x64_get_booting_ap();

    x64_fpu_init_bsp();
    x64_init_gdt_bsp();
    x64_init_idt_bsp();

    /*
     * Tricky Ordering here because technically there is
     * a cyclic dependency between the percpu variables subsystem
     * and the vmem subsystem
     */

    // We need to activate the default vmem_map to get access to the heap,
    // (call the arch_vmem_* function directly to skip over the vmem subsystem)
    struct vmem_map *default_map = vmem_get_default_map();
    arch_vmem_map_activate(default_map);

    // Then we can enable percpu variables
    struct cpu *self_gen_cpu = cpu_from_id(self);
    arch_set_percpu_area(self, self_gen_cpu->percpu_data);
    set_current_cpu_id(self);

    // And finally we can setup the vmem subsystem correctly
    res = vmem_percpu_init();
    if(res) {
        eprintk("AP(%ld) vmem_percpu_init Failed! (err=%s)\n",
                (sl_t)self, errnostr(res));
        panic("AP Init Failed!\n");
    }

    printk("Starting threading on CPU (%ld)\n",
            (long)current_cpu_id());

    cpu_start_threading(x64_ap_init, NULL); 
}

void x64_ap_init(void *old_stack)
{
    int res;

    res = lapic_init_current();
    if(res) {
        panic("CPU %ld Failed to initialize the LAPIC!\n",
                (sl_t)current_cpu_id());
    }
    res = apic_timer_init_current();
    if(res) {
        panic("CPU %ld Failed to initialize the APIC Timer!\n",
                (sl_t)current_cpu_id());
    }

    x64_ap_notify_booted();

    printk("CPU (%ld) init thread is idling\n", (sl_t)current_cpu_id());
    idle_loop();

    panic("Returned from idle thread abandon!\n");
}

