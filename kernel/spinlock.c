
#include <kanawha/cpu.h>
#include <kanawha/init.h>
#include <kanawha/irq.h>
#include <kanawha/spinlock.h>

void
spinlock_failed_loop(spinlock_t *lock)
{
    if(!irqs_enabled() && total_num_cpus() <= 1)
    {
        panic("DEADLOCK: Single CPU is spinning on lock (%p) without "
              "interrupts enabled!\n",
              (void *)lock);
    }
}
