
#include <arch/x64/exception.h>
#include <arch/x64/sysreg.h>
#include <kanawha/printk.h>
#include <kanawha/irq.h>
#include <kanawha/irq_domain.h>
#include <kanawha/init.h>
#include <kanawha/atomic.h>
#include <kanawha/percpu.h>
#include <kanawha/excp.h>
#include <kanawha/scheduler.h>
#include <kanawha/thread.h>
#include <kanawha/assert.h>

struct irq_domain *x64_vector_irq_domain = NULL;

static int
x64_alloc_vector_irq_domain(void)
{
    x64_vector_irq_domain = 
        alloc_irq_domain_linear(0, 256);
    if(x64_vector_irq_domain == NULL) {
        return -ENOMEM;
    }

    return 0;
}

declare_init_desc(dynamic, x64_alloc_vector_irq_domain, "Creating x64 Vector IRQ Domain");

irq_t x64_request_irq_vector(void)
{
    hwirq_t hwirq = 0xFE; // 0xFF should be assigned to the spurrious vector
    struct irq_desc *min_desc = NULL;
    for(; hwirq >= 32; hwirq--) {
        irq_t irq = irq_domain_revmap(x64_vector_irq_domain, hwirq);
        struct irq_desc *desc = irq_to_desc(irq);
        if(desc->num_actions == 0) {
            return desc->irq;
        }
        else if(min_desc == NULL || desc->num_actions < min_desc->num_actions) {
            min_desc = desc;
        }
    }

    // This should realistically never happen

    if(min_desc == NULL) {
        return NULL_IRQ;
    }
    return min_desc->irq;
}

__attribute__((noreturn))
void
x64_unhandled_exception(struct x64_excp_state *state)
{
    const char *mnemonic = "UNKNOWN";
    const char *desc_str = "Unknown-Vector";
    int errcode_valid = 0;
    int type = X64_EXCP_TYPE_UNDEF;

    switch(state->vector) {
#define UNHANDLED_EXCEPTION_CASE(VECTOR,MNEMONIC,DESC_STR,ERRCODE_VALID,TYPE)\
        case VECTOR:\
            mnemonic = #MNEMONIC;\
            desc_str = DESC_STR;\
            errcode_valid = ERRCODE_VALID;\
            type = TYPE;\
            break;
X64_EXCP_XLIST(UNHANDLED_EXCEPTION_CASE)
#undef UNHANDLED_EXCEPTION_CASE
    }

    printk("===== UNHANDLED \"%s\" EXCEPTION ===== (#%s)\n", desc_str, mnemonic);
    printk("\tVECTOR=0x%x", state->vector);
    if(errcode_valid) {
        printk(", ERR=0x%x", (unsigned)state->error_code);
    }
    printk("\n");
    printk("\tRFLAGS=%p\n", (uintptr_t)state->rflags);
    printk("\tRIP=%p\n", (uintptr_t)state->rip);
    printk("\tCS=%p\n", (uintptr_t)state->cs);
    printk("\tCR2 = %p\n", (void *)read_cr2());

    panic("Unhandled %s Exception! (vector=0x%x)\n", desc_str, (unsigned)state->vector);
}

__attribute__((noreturn))
static void
x64_unhandled_interrupt(struct x64_excp_state *state)
{
    panic("Unhandled Interrupt! (vector=0x%x)\n", (unsigned)state->vector);
}

void x64_handle_exception(struct x64_excp_state *state)
{
    dprintk("CPU (%ld) exception 0x%lx state=%p\n",
            (sl_t)current_cpu_id(),
            (ul_t)state->vector,
            state);

    DEBUG_ASSERT(
            (uintptr_t)(current_thread()->arch_state.kernel_rsp)
            > (uintptr_t)(current_thread()->arch_state.kernel_stack_top));

    if(x64_vector_irq_domain == NULL) {
        eprintk("Exception or Interrupt (0x%lx) Occurred before x64_vector_irq_domain has been initialized on CPU (%ld)\n",
                (ul_t)state->vector, (sl_t)current_cpu_id());
        if(state->vector < 32) {
            x64_unhandled_exception(state);
        } else {
            x64_unhandled_interrupt(state);
        }
        return;
    }

    struct irq_desc *desc = x64_vector_irq_desc(state->vector);

    if(desc == NULL) {
        eprintk("Failed to get irq_desc for x64 vector 0x%lx on CPU (%ld)\n",
                (ul_t)state->vector, (sl_t)current_cpu_id());
        if(state->vector < 32) {
            x64_unhandled_exception(state);
        } else {
            x64_unhandled_interrupt(state);
        }
        return;
    }

    struct excp_state *excp_state = (struct excp_state*)state;

    int res = handle_irq(desc, excp_state);
    if(res == IRQ_UNHANDLED) {
        eprintk("Failed to handle IRQ 0x%lx (vector=0x%lx) on CPU (%ld)\n",
                (ul_t)desc->irq, (ul_t)state->vector, (sl_t)current_cpu_id());
        if(state->vector < 32) {
            x64_unhandled_exception(state);
        } else {
            x64_unhandled_interrupt(state);
        } 
        return;
    }

    struct thread_state *new_thread = query_resched();
    if(new_thread != NULL) {

        //printk("CPU (%ld) Interrupt Driven Thread Switch old=%p, new=%p\n",
        //        (sl_t)current_cpu_id(),
        //        current_thread(),
        //        new_thread);

        x64_nop_iret();
        thread_switch(new_thread);

        // We will eventually return and restore our registers off the stack
        // when we start running this thread again.
    } else {
        //printk("CPU (%ld) No Interrupt Driven Thread Switch\n",
        //        (sl_t)current_cpu_id());
    }

    return;
}

void
arch_excp_dump_state(struct excp_state *gen_state, printk_f *printer) {
    struct x64_excp_state *state = (struct x64_excp_state*)gen_state;

    int errcode_valid;
    switch(state->vector) {
#define UNHANDLED_EXCEPTION_CASE(VECTOR,MNEMONIC,DESC_STR,ERRCODE_VALID,TYPE)\
        case VECTOR:\
            errcode_valid = ERRCODE_VALID;\
            break;
X64_EXCP_XLIST(UNHANDLED_EXCEPTION_CASE)
#undef UNHANDLED_EXCEPTION_CASE
    }

    printk("\tVECTOR=0x%x", state->vector);
    if(errcode_valid) {
        printk(", ERR=0x%x", (unsigned)state->error_code);
    }
    printk("\tRFLAGS=%p\n", (uintptr_t)state->rflags);
    printk("\tRIP=%p\n", (uintptr_t)state->rip);
    printk("\tCS=%p\n", (uintptr_t)state->cs);
}

