
#include <arch/x64/fpu.h>
#include <arch/x64/sysreg.h>
#include <arch/x64/exception.h>
#include <kanawha/irq.h>
#include <kanawha/thread.h>
#include <kanawha/init.h>
#include <kanawha/scheduler.h>
#include <kanawha/proc/process.h>

static int
x64_fpu_init_any(void) 
{
    uint32_t cr0 = read_cr0();
    cr0 &= ~(1UL << 2); // Disable x87 Emulation
    cr0 &= ~(1UL << 3); // Disable Task Switch Trapping
    cr0 |=  (1UL << 4); // 387 or later (probably already hardwired)
    write_cr0(cr0);

    uint64_t cr4 = read_cr4();
    cr4 |=  (1UL << 9); // Enable 128-bit SSE
    cr4 |=  (1UL << 10); // Enable 128-bit SSE Exceptions
    write_cr4(cr4);

    write_mxcsr(
            MXCSR_INVALID_OP_MASK|
            MXCSR_DENORMAL_OP_MASK|
            MXCSR_DIV_BY_ZERO_MASK|
            MXCSR_OVERFLOW_MASK|
            MXCSR_UNDERFLOW_MASK|
            MXCSR_PRECISION_MASK
            );

    return 0;
}

int x64_fpu_init_bsp(void) 
{
    return x64_fpu_init_any();
}

int x64_fpu_init_ap(void) 
{
    return x64_fpu_init_any();
}

int x64_fpu_per_process_init(void)
{
    write_mxcsr(
            MXCSR_INVALID_OP_MASK|
            MXCSR_DENORMAL_OP_MASK|
            MXCSR_DIV_BY_ZERO_MASK|
            MXCSR_OVERFLOW_MASK|
            MXCSR_UNDERFLOW_MASK|
            MXCSR_PRECISION_MASK
            );
    return 0;
}

static struct irq_action *x64_simd_fault_action = NULL;

static int
x64_simd_fault_handler(
        struct excp_state *gen_excp_state,
        struct irq_action *action)
{
    int res;
    
    struct x64_excp_state *excp_state =
        (struct x64_excp_state*)gen_excp_state;

    int ring_from = excp_state->cs & 0b11;
    if(ring_from == 0) {
        return IRQ_UNHANDLED;
    }

    struct process *process = current_process();
    if(process == NULL) {
        return IRQ_UNHANDLED;
    }

    uint32_t mxcsr = read_mxcsr();
    printk("Delivering SIMD Fault to Process! (MXCSR=0x%lx)\n",
            (ul_t)mxcsr);

    res = signal_deliver(process, SIGNAL_ID_PROTFAULT, 0);
    if(res) {
        eprintk("Failed to deliver PROTFAULT signal to process on SIMD fault (user_ip=%p) (err=%s)!\n",
                process->user_ip,
                errnostr(res));
        res = process_terminate(-EFAULT);
        if(res) {
            eprintk("Failed to terminate process which could not be delivered PROTFAULT (err=%s)\n",
                    errnostr(res));
            return res;
        }
        thread_abandon(force_resched());
    }

    return IRQ_HANDLED;
}

static int
x64_install_simd_fault_handler(void)
{
    // Defer as long as the vector domain is still NULL
    if(x64_vector_irq_domain == NULL) {
        return -EDEFER;
    }

    x64_simd_fault_action =
        irq_install_handler(
            x64_vector_irq_desc(19),
            NULL, // priv_state
            x64_simd_fault_handler);

    if(x64_simd_fault_action == NULL) {
        return -EINVAL;
    }
    return 0;
}
declare_init_desc(dynamic, x64_install_simd_fault_handler, "Installing x64 SIMD Fault Handler");

