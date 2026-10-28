
#include <kanawha/excp.h>
#include <kanawha/irq_domain.h>
#include <kanawha/printk.h>

void
unhandled_interrupt(struct excp_state *state)
{
    struct printer *printer = printk_printer();
#if defined(CONFIG_UNHANDLED_IRQ_PANIC)
    // dump_irq_descs(do_panic_printk);
    arch_excp_dump_state(state, printer);
    panic("Unhandled Interrupt!");
#elif defined(CONFIG_UNHANDLED_IRQ_IGNORE)
    // Do nothing
#elif defined(CONFIG_UNHANDLED_IRQ_WARN)
    // arch_excp_dump_state(state, printer);
    wprintk("Unhandled Interrupt!\n");
#else
#error                                                                         \
    "Configuration did not specify response to an unhandled interrupt (Select one of PANIC/IGNORE/WARN)!"
#endif
}
