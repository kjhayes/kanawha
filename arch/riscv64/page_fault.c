
#include <arch/riscv64/trap.h>
#include <arch/riscv64/csr.h>
#include <kanawha/init.h>
#include <kanawha/irq.h>
#include <kanawha/excp.h>
#include <kanawha/irq_domain.h>
#include <kanawha/vmem.h>

#define RISCV64_EXCP_PF_INSTR 12
#define RISCV64_EXCP_PF_LOAD  13
#define RISCV64_EXCP_PF_STORE 15

struct irq_action *riscv64_pf_action_instr = NULL;
struct irq_action *riscv64_pf_action_load  = NULL;
struct irq_action *riscv64_pf_action_store = NULL;

static int
riscv64_vmem_page_fault_handler(
        struct excp_state *gen_excp_state,
        struct irq_action *action)
{
    int res;

    struct riscv64_excp_state *state =
        (struct riscv64_excp_state *)gen_excp_state;

    struct vmem_map *cur_map = vmem_map_get_current();
    DEBUG_ASSERT(KERNEL_ADDR(cur_map));

    //arch_dump_vmem_map(do_printk, cur_map);

    unsigned long flags = 0;
    switch(action->desc->hwirq) {
        case RISCV64_EXCP_PF_STORE:
            flags |= PF_FLAG_WRITE;
            break;
        case RISCV64_EXCP_PF_LOAD:
            flags |= PF_FLAG_READ;
            break;
        case RISCV64_EXCP_PF_INSTR:
            flags |= PF_FLAG_EXEC;
            break;
        default:
            panic("riscv64_vmem_page_fault_handler: invoked with invalid hwirq=0x%lx\n",
                    (ul_t)action->desc->hwirq);
    }

    uint64_t sstatus = read_csr(sstatus);

    if(!(sstatus & (1ULL<<8))) {
        // Previous mode was usermode
        flags |= PF_FLAG_USERMODE;
    }

    void *faulting_addr = (void*)state->stval;

    // We need to walk the page table to determine if the page is present
    int present = riscv64_vmem_map_page_is_present(cur_map, faulting_addr);
    if(present < 0) {
        panic("Invalid page table found on page fault table walk! (faulting_addr=%p)\n",
                faulting_addr);
    }

    if(!present) {
        flags |= PF_FLAG_NOT_PRESENT;
    }

    res = vmem_map_handle_page_fault(
            gen_excp_state,
            faulting_addr,
            flags,
            cur_map);
    if(res) {
        //arch_dump_vmem_map(do_printk, cur_map);
        return IRQ_UNHANDLED;
    }

    return IRQ_HANDLED;
}

static int
riscv64_install_page_fault_handler(void)
{
    if(riscv64_exception_irq_domain == NULL) {
        return -EDEFER;
    }

    struct irq_desc *desc;

    desc = riscv64_exception_irq_desc(RISCV64_EXCP_PF_INSTR);
    if(desc == NULL) {
        return -EINVAL;
    }
    riscv64_pf_action_instr =
        irq_install_handler(
            desc,
            NULL, // priv_state
            riscv64_vmem_page_fault_handler);
    if(riscv64_pf_action_instr == NULL) {
        return -EINVAL;
    }
    desc = riscv64_exception_irq_desc(RISCV64_EXCP_PF_LOAD);
    if(desc == NULL) {
        return -EINVAL;
    }
    riscv64_pf_action_load =
        irq_install_handler(
            desc,
            NULL, // priv_state
            riscv64_vmem_page_fault_handler);
    if(riscv64_pf_action_load == NULL) {
        return -EINVAL;
    }
    desc = riscv64_exception_irq_desc(RISCV64_EXCP_PF_STORE);
    if(desc == NULL) {
        return -EINVAL;
    }
    riscv64_pf_action_store =
        irq_install_handler(
            desc,
            NULL, // priv_state
            riscv64_vmem_page_fault_handler);
    if(riscv64_pf_action_store == NULL) {
        return -EINVAL;
    }

    return 0;
}
declare_init_desc(dynamic, riscv64_install_page_fault_handler, "Installing RISC-V Page Fault Handler(s)");

