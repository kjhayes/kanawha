
#include <kanawha/export.h>
#include <kanawha/panic.h>
#include <kanawha/proc/process.h>
#include <kanawha/xcall.h>

static void
alt_cpu_panic_halt(void *cpu_id_ptr)
{
    disable_irqs();

    cpu_id_t panic_cpu = *(cpu_id_t *)cpu_id_ptr;
    if(panic_cpu == current_cpu_id())
    {
        return;
    }

    while(1)
    {
        disable_irqs();
        halt();
    }
}

__noreturn void
do_panic(void)
{
    disable_irqs();

    // Stop all other CPU(s)
    cpu_id_t current = current_cpu_id();
    xcall_broadcast(alt_cpu_panic_halt, &current);

    do_panic_printk(" CPU(%ld) Stopped All Other CPU(s)\n", (long)current);

    do_panic_printk(" THREAD(");
    if(current_thread())
    {
        do_panic_printk("%lld", (ull_t)current_thread()->id);
    }
    else
    {
        do_panic_printk("NULL");
    }
    do_panic_printk(")");
    if(current_process())
    {
        do_panic_printk(" PROCESS(%lld)", (ull_t)current_process()->id);
    }
    do_panic_printk("\n");

    dump_threads(do_panic_printk);

    while(1)
    {
        disable_irqs();
        halt();
    }
}

EXPORT_SYMBOL(do_panic);
