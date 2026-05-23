
#include <arch/riscv64/csr.h>
#include <arch/riscv64/trap.h>
#include <kanawha/attribute.h>
#include <kanawha/init.h>
#include <kanawha/irq.h>
#include <kanawha/irq_domain.h>
#include <kanawha/printk.h>
#include <kanawha/proc/process.h>
#include <kanawha/scheduler.h>
#include <kanawha/thread.h>

extern void
__riscv64_trap_entry(void);

static const char *
riscv64_scause_desc(uint64_t scause)
{
#define SCAUSE_CASE(__NUM, __STR)                                              \
    case __NUM:                                                                \
        return __STR;

    int interrupt = !!(scause & (1ULL << 63));
    uint64_t code = scause & ~(1ULL << 63);
    if(interrupt)
    {
        switch(code)
        {
            RISCV64_INTERRUPT_XLIST(SCAUSE_CASE);
        default:
            return "Unknown Interrupt";
        }
    }
    else
    {
        switch(code)
        {
            RISCV64_EXCEPTION_XLIST(SCAUSE_CASE);
        default:
            return "Unknown Exception";
        }
    }
#undef SCAUSE_CASE
}

#define STVEC_MODE_MASK 0b11
#define STVEC_DIRECT 0b00
#define STVEC_VECTORED 0b01

int
riscv64_boot_setup_stvec(void)
{

    uint64_t stvec_value = (uintptr_t)__riscv64_trap_entry;

    // Clear the mode bits
    // (Should do nothing if we assume the handler is properly aligned)
    stvec_value &= ~0b11;

    stvec_value |= STVEC_DIRECT;

    write_csr(stvec, stvec_value);
    return 0;
}

declare_init_desc(boot,
                  riscv64_boot_setup_stvec,
                  "Setting Up RISC-V Trap Vector");

struct irq_domain *riscv64_exception_irq_domain = NULL;
struct irq_domain *riscv64_interrupt_irq_domain = NULL;

static int
riscv64_alloc_root_irq_domains(void)
{
    riscv64_exception_irq_domain =
        alloc_irq_domain_linear(0, RISCV64_EXCEPTION_IRQ_DOMAIN_SIZE);
    if(riscv64_exception_irq_domain == NULL)
    {
        return -ENOMEM;
    }
    riscv64_interrupt_irq_domain =
        alloc_irq_domain_linear(0, RISCV64_INTERRUPT_IRQ_DOMAIN_SIZE);
    if(riscv64_interrupt_irq_domain == NULL)
    {
        return -ENOMEM;
    }
    return 0;
}
declare_init_desc(dynamic,
                  riscv64_alloc_root_irq_domains,
                  "Creating RISC-V Root IRQ Domains");

__noreturn static void
riscv64_unhandled_trap(struct riscv64_excp_state *state)
{
    const char *excp_desc = riscv64_scause_desc(state->scause);

    printk("==== UNHANDLED \"%s\" TRAP ====\n", excp_desc);

    printk("\tSCAUSE  = %p\n", state->scause);
    printk("\tSTVAL   = %p\n", state->stval);
    printk("\tSEPC    = %p\n", state->sepc);
    printk("\tSSTATUS = %p\n", state->sstatus);

    dump_threads(do_panic_printk);

    panic("Unhandled Exception!\n");
}

static void
riscv64_unhandled_interrupt(struct riscv64_excp_state *state)
{
    unhandled_interrupt((struct excp_state *)state);
}

void
riscv64_route_trap(struct riscv64_excp_state *state)
{
    struct thread_state *cur_thread = current_thread();
    struct thread_state *new_thread;

    if((state->sstatus & SSTATUS_MASK_SPP) == 0)
    {
        struct process *process = current_process();
        DEBUG_ASSERT(KERNEL_ADDR(process));
        process->user_ip = (void __user *)state->sepc;
    }

    struct irq_desc *desc = NULL;

    int is_interrupt = !!(state->scause & (1ULL << 63));
    hwirq_t hwirq = state->scause & ~(1ULL << 63);
    if(!is_interrupt && hwirq >= 64)
    {
        eprintk("riscv64_route_trap: exception with cause >=64! "
                "(scause=0x%lx)\n",
                state->scause);
        riscv64_unhandled_trap(state);
    }

    if(is_interrupt)
    {
        if(riscv64_interrupt_irq_domain == NULL)
        {
            eprintk("riscv64_route_trap: Interrupt occurred before "
                    "setting up "
                    "root interrupt IRQ domain!\n");
            riscv64_unhandled_interrupt(state);
            goto exit;
        }
        irq_t irq = irq_domain_revmap(riscv64_interrupt_irq_domain, hwirq);
        if(irq == NULL_IRQ)
        {
            eprintk("riscv64_route_trap: Failed to map root interrupt "
                    "hwirq=0x%lx!\n",
                    (ul_t)hwirq);
            riscv64_unhandled_interrupt(state);
            goto exit;
        }
        desc = irq_to_desc(irq);

        if(desc == NULL)
        {
            eprintk("riscv64_route_trap: Failed to get root interrupt IRQ "
                    "descriptor!\n");
            riscv64_unhandled_interrupt(state);
            goto exit;
        }
    }
    else
    {
        if(riscv64_exception_irq_domain == NULL)
        {
            eprintk("riscv64_route_trap: Exception occurred before "
                    "setting up "
                    "root exception IRQ domain!\n");
            riscv64_unhandled_trap(state);
        }
        irq_t irq = irq_domain_revmap(riscv64_exception_irq_domain, hwirq);
        if(irq == NULL_IRQ)
        {
            eprintk("riscv64_route_trap: Failed to map root exception "
                    "hwirq=0x%lx!\n",
                    (ul_t)hwirq);
            riscv64_unhandled_trap(state);
        }
        desc = irq_to_desc(irq);

        if(desc == NULL)
        {
            eprintk("riscv64_route_trap: Failed to get root trap IRQ "
                    "descriptor!\n");
            riscv64_unhandled_trap(state);
        }
    }

    dprintk("hwirq=0x%lx, num_actions=0x%lx\n", desc->hwirq, desc->num_actions);

    int res = handle_irq(desc, (struct excp_state *)state);
    if(res == IRQ_UNHANDLED)
    {
        if(is_interrupt)
        {
            riscv64_unhandled_interrupt(state);
            goto exit;
        }
        else
        {
            eprintk("Failed to handle IRQ 0x%lx (scause=0x%lx) on "
                    "CPU (%ld)\n",
                    (ul_t)desc->irq,
                    (ul_t)state->scause,
                    (sl_t)current_cpu_id());
            riscv64_unhandled_trap(state);
        }
    }

exit:
    soft_resched();
    if(current_thread_is_rescheduled())
    {
        thread_switch();
    }
    else
    {
        // No thread switch
    }

    return;

    //    panic("RISC-V Trap! (sepc=%p, scause=0x%lx, stval=0x%lx)\n",
    //            state->sepc,
    //            state->scause,
    //            state->stval);
}

struct irq_desc *
riscv64_exception_irq_desc(hwirq_t hwirq)
{
    if(riscv64_exception_irq_domain == NULL)
    {
        return NULL;
    }
    irq_t irq = irq_domain_revmap(riscv64_exception_irq_domain, hwirq);
    if(irq == NULL_IRQ)
    {
        return NULL;
    }
    return irq_to_desc(irq);
}

struct irq_desc *
riscv64_interrupt_irq_desc(hwirq_t hwirq)
{
    if(riscv64_interrupt_irq_domain == NULL)
    {
        return NULL;
    }
    irq_t irq = irq_domain_revmap(riscv64_interrupt_irq_domain, hwirq);
    if(irq == NULL_IRQ)
    {
        return NULL;
    }
    return irq_to_desc(irq);
}

struct irq_domain *
riscv64_shared_interrupt_domain(void)
{
    return riscv64_interrupt_irq_domain;
}
struct irq_domain *
riscv64_shared_exception_domain(void)
{
    return riscv64_exception_irq_domain;
}

void
arch_excp_dump_state(struct excp_state *gen_excp_state, printk_f *printer)
{
    struct riscv64_excp_state *state = (void *)gen_excp_state;

    (*printer)("\tSCAUSE = %p\n", state->scause);
    (*printer)("\tSTVAL  = %p\n", state->stval);
    (*printer)("\tSEPC   = %p\n", state->sepc);
}
