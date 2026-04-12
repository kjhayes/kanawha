
#include <kanawha/irq.h>
#include <kanawha/irq_domain.h>
#include <kanawha/vmem.h>
#include <kanawha/init.h>
#include <arch/x64/sysreg.h>
#include <arch/x64/exception.h>

static struct irq_action *x64_pf_action = NULL;

static int
x64_vmem_page_fault_handler(struct excp_state *gen_excp_state,
                            struct irq_action *action)
{
    int res;

    uintptr_t faulting_address = (uintptr_t)read_cr2();
    struct vmem_map *current = vmem_map_get_current();

    struct x64_excp_state *excp_state = (struct x64_excp_state *)gen_excp_state;

    unsigned long pf_flags = 0;

    pf_flags |=
        (excp_state->error_code & (1ULL << 0)) == 0 ? PF_FLAG_NOT_PRESENT : 0;
    pf_flags |= (excp_state->error_code & (1ULL << 1)) == 0 ? PF_FLAG_READ : 0;
    pf_flags |= excp_state->error_code & (1ULL << 1) ? PF_FLAG_WRITE : 0;
    pf_flags |= excp_state->error_code & (1ULL << 2) ? PF_FLAG_USERMODE : 0;
    pf_flags |= excp_state->error_code & (1ULL << 4) ? PF_FLAG_EXEC : 0;

    res = vmem_map_handle_page_fault(gen_excp_state,
                                     (void *)faulting_address,
                                     pf_flags,
                                     current);

    if(res)
    {

        // Kernel Fault ((noreturn))
        eprintk("x64_vmem_page_fault_handler: Failed to handle page fault "
                "(err=%s)\n",
                errnostr(res));

        x64_unhandled_exception((struct x64_excp_state *)excp_state);

        // This should never happen but let's be safe
        return -EINVAL;
    }

    dprintk("Page Fault Handled!\n");
    return IRQ_HANDLED;
}

static int
x64_install_page_fault_handler(void)
{
    // Defer as long as the vector domain is still NULL
    if(x64_vector_irq_domain == NULL)
    {
        return -EDEFER;
    }

    x64_pf_action = irq_install_handler(x64_vector_irq_desc(14),
                                        NULL, // priv_state
                                        x64_vmem_page_fault_handler);

    if(x64_pf_action == NULL)
    {
        return -EINVAL;
    }
    return 0;
}
declare_init_desc(dynamic,
                  x64_install_page_fault_handler,
                  "Installing x64 Page Fault Handler");

