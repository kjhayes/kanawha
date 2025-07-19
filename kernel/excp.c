
#include <kanawha/excp.h>

void unhandled_interrupt(struct excp_state *state)
{
#if defined(CONFIG_UNHANDLED_IRQ_PANIC)
    arch_excp_dump_state(state, do_panic_printk);
    panic("Unhandled Interrupt!");
#elif defined(CONFIG_UNHANDLED_IRQ_IGNORE)
    // Do nothing
#elif defined(CONFIG_UNHANDLED_IRQ_WARN)
    arch_excp_dump_state(state, do_printk)
    wprintk("Unhandled Interrupt!\n");
#else
#error "Configuration did not specify response to an unhandled interrupt (Select one of PANIC/IGNORE/WARN)!"
#endif
}

