
#include <kanawha/excp.h>
#include <kanawha/irq_domain.h>
#include <arch/arm64/sysreg.h>
#include <arch/arm64/excp.h>
#include <arch/arm64/asm/regs.h>
#include <kanawha/syscall.h>

static int
arm64_handle_svc64(
        struct arm64_excp_state *state,
        struct irq_action *action,
        uint64_t iss)
{
    int res;

    if(iss != 0) {
        return IRQ_UNHANDLED;
    }

    struct syscall_args args;
    args.args[0] = state->caller_regs[ARM64_PUSHED_CALLER_REG_INDEX_X0];
    args.args[1] = state->caller_regs[ARM64_PUSHED_CALLER_REG_INDEX_X1];
    args.args[2] = state->caller_regs[ARM64_PUSHED_CALLER_REG_INDEX_X2];
    args.args[3] = state->caller_regs[ARM64_PUSHED_CALLER_REG_INDEX_X3];
    args.args[4] = state->caller_regs[ARM64_PUSHED_CALLER_REG_INDEX_X4];
    args.args[5] = state->caller_regs[ARM64_PUSHED_CALLER_REG_INDEX_X5];

    struct process *process = current_process();

    enable_irqs();
    res = handle_syscall(
            state->caller_regs[ARM64_PUSHED_CALLER_REG_INDEX_X8],
            &args,
            &state->caller_regs[ARM64_PUSHED_CALLER_REG_INDEX_X0]);
    disable_irqs();
    if(res) {
        return IRQ_UNHANDLED;
    }

    return IRQ_HANDLED;
}

#define ARM64_IFSC_XLIST(X,...)\
X(ADDRESS_SIZE_FAULT_L0, 0b000000, ##__VA_ARGS__)\
X(ADDRESS_SIZE_FAULT_L1, 0b000001, ##__VA_ARGS__)\
X(ADDRESS_SIZE_FAULT_L2, 0b000010, ##__VA_ARGS__)\
X(ADDRESS_SIZE_FAULT_L3, 0b000011, ##__VA_ARGS__)\
X(TRANSLATION_FAULT_L0,  0b000100, ##__VA_ARGS__)\
X(TRANSLATION_FAULT_L1,  0b000101, ##__VA_ARGS__)\
X(TRANSLATION_FAULT_L2,  0b000110, ##__VA_ARGS__)\
X(TRANSLATION_FAULT_L3,  0b000111, ##__VA_ARGS__)\
X(ACCESS_FLAG_FAULT_L1,  0b001001, ##__VA_ARGS__)\
X(ACCESS_FLAG_FAULT_L2,  0b001010, ##__VA_ARGS__)\
X(ACCESS_FLAG_FAULT_L3,  0b001011, ##__VA_ARGS__)\
X(ACCESS_FLAG_FAULT_L0,  0b001000, ##__VA_ARGS__)\
X(PERMISSION_FAULT_L0,   0b001100, ##__VA_ARGS__)\
X(PERMISSION_FAULT_L1,   0b001101, ##__VA_ARGS__)\
X(PERMISSION_FAULT_L2,   0b001110, ##__VA_ARGS__)\
X(PERMISSION_FAULT_L3,   0b001111, ##__VA_ARGS__)\

enum {
#define ARM64_IFSC_DECLARE_ENUM(__NAME, __VALUE, ...)\
    ARM64_IFSC_ ## __NAME = __VALUE,
    ARM64_IFSC_XLIST(ARM64_IFSC_DECLARE_ENUM)
#undef ARM64_IFSC_DECLARE_ENUM
};

static inline const char *
arm64_ifsc_to_string(unsigned long value)
{
    switch(value) {
#define ARM64_IFSC_DECLARE_TO_STRING_CASE(__NAME, __VALUE, ...)\
        case ARM64_IFSC_ ## __NAME: return #__NAME;
    ARM64_IFSC_XLIST(ARM64_IFSC_DECLARE_TO_STRING_CASE)
#undef ARM64_IFSC_DECLARE_TO_STRING_CASE
        default: return "UNKNOWN";
    }
}

static int
arm64_handle_instruction_abort(
        struct arm64_excp_state *state,
        struct irq_action *action,
        int el,
        uint64_t iss)
{
    int res;
    unsigned long pf_flags = PF_FLAG_EXEC;
    if(el == 0) {
        pf_flags |= PF_FLAG_USERMODE;
    }
    uint64_t ifsc = iss & 0x3F;
    switch(ifsc) {
        case ARM64_IFSC_ADDRESS_SIZE_FAULT_L0:
        case ARM64_IFSC_ADDRESS_SIZE_FAULT_L1:
        case ARM64_IFSC_ADDRESS_SIZE_FAULT_L2:
        case ARM64_IFSC_ADDRESS_SIZE_FAULT_L3:
            pf_flags |= PF_FLAG_NOT_PRESENT;
            break;
        case ARM64_IFSC_TRANSLATION_FAULT_L0:
        case ARM64_IFSC_TRANSLATION_FAULT_L1:
        case ARM64_IFSC_TRANSLATION_FAULT_L2:
        case ARM64_IFSC_TRANSLATION_FAULT_L3:
            pf_flags |= PF_FLAG_NOT_PRESENT;
            break;
        case ARM64_IFSC_ACCESS_FLAG_FAULT_L0:
        case ARM64_IFSC_ACCESS_FLAG_FAULT_L1:
        case ARM64_IFSC_ACCESS_FLAG_FAULT_L2:
        case ARM64_IFSC_ACCESS_FLAG_FAULT_L3:
            pf_flags |= PF_FLAG_NOT_PRESENT;
            break;
        case ARM64_IFSC_PERMISSION_FAULT_L0:
        case ARM64_IFSC_PERMISSION_FAULT_L1:
        case ARM64_IFSC_PERMISSION_FAULT_L2:
        case ARM64_IFSC_PERMISSION_FAULT_L3:
            pf_flags |= PF_FLAG_USERMODE;
            break;
        default:
            eprintk("ARM64: unhandled IFSC on instruction abort: %s\n",
                    arm64_ifsc_to_string(ifsc));
            return IRQ_UNHANDLED;
    }

    res = vmem_map_handle_page_fault(
            (struct excp_state *)state,
            (void*)state->far,
            pf_flags,
            vmem_map_get_current());
    if(res) {
        return IRQ_UNHANDLED;
    }

    return IRQ_HANDLED;
}

#define ARM64_DFSC_XLIST(X,...)\
X(ADDRESS_SIZE_FAULT_L0, 0b000000, ##__VA_ARGS__)\
X(ADDRESS_SIZE_FAULT_L1, 0b000001, ##__VA_ARGS__)\
X(ADDRESS_SIZE_FAULT_L2, 0b000010, ##__VA_ARGS__)\
X(ADDRESS_SIZE_FAULT_L3, 0b000011, ##__VA_ARGS__)\
X(TRANSLATION_FAULT_L0,  0b000100, ##__VA_ARGS__)\
X(TRANSLATION_FAULT_L1,  0b000101, ##__VA_ARGS__)\
X(TRANSLATION_FAULT_L2,  0b000110, ##__VA_ARGS__)\
X(TRANSLATION_FAULT_L3,  0b000111, ##__VA_ARGS__)\
X(ACCESS_FLAG_FAULT_L1,  0b001001, ##__VA_ARGS__)\
X(ACCESS_FLAG_FAULT_L2,  0b001010, ##__VA_ARGS__)\
X(ACCESS_FLAG_FAULT_L3,  0b001011, ##__VA_ARGS__)\
X(ACCESS_FLAG_FAULT_L0,  0b001000, ##__VA_ARGS__)\
X(PERMISSION_FAULT_L0,   0b001100, ##__VA_ARGS__)\
X(PERMISSION_FAULT_L1,   0b001101, ##__VA_ARGS__)\
X(PERMISSION_FAULT_L2,   0b001110, ##__VA_ARGS__)\
X(PERMISSION_FAULT_L3,   0b001111, ##__VA_ARGS__)\

enum {
#define ARM64_DFSC_DECLARE_ENUM(__NAME, __VALUE, ...)\
    ARM64_DFSC_ ## __NAME = __VALUE,
    ARM64_DFSC_XLIST(ARM64_DFSC_DECLARE_ENUM)
#undef ARM64_DFSC_DECLARE_ENUM
};

static inline const char *
arm64_dfsc_to_string(unsigned long value)
{
    switch(value) {
#define ARM64_DFSC_DECLARE_TO_STRING_CASE(__NAME, __VALUE, ...)\
        case ARM64_DFSC_ ## __NAME: return #__NAME;
    ARM64_DFSC_XLIST(ARM64_DFSC_DECLARE_TO_STRING_CASE)
#undef ARM64_DFSC_DECLARE_TO_STRING_CASE
        default: return "UNKNOWN";
    }
}

static int
arm64_handle_data_abort(
        struct arm64_excp_state *state,
        struct irq_action *action,
        int el,
        uint64_t iss)
{
    int res;
    unsigned long pf_flags = 0;
    if(el == 0) {
        pf_flags |= PF_FLAG_USERMODE;
    }
    uint64_t dfsc = iss & 0x3F;
    switch(dfsc) {
        case ARM64_DFSC_ADDRESS_SIZE_FAULT_L0:
        case ARM64_DFSC_ADDRESS_SIZE_FAULT_L1:
        case ARM64_DFSC_ADDRESS_SIZE_FAULT_L2:
        case ARM64_DFSC_ADDRESS_SIZE_FAULT_L3:
            pf_flags |= PF_FLAG_NOT_PRESENT;
            break;
        case ARM64_DFSC_TRANSLATION_FAULT_L0:
        case ARM64_DFSC_TRANSLATION_FAULT_L1:
        case ARM64_DFSC_TRANSLATION_FAULT_L2:
        case ARM64_DFSC_TRANSLATION_FAULT_L3:
            pf_flags |= PF_FLAG_NOT_PRESENT;
            break;
        case ARM64_DFSC_ACCESS_FLAG_FAULT_L0:
        case ARM64_DFSC_ACCESS_FLAG_FAULT_L1:
        case ARM64_DFSC_ACCESS_FLAG_FAULT_L2:
        case ARM64_DFSC_ACCESS_FLAG_FAULT_L3:
            pf_flags |= PF_FLAG_NOT_PRESENT;
            break;
        case ARM64_DFSC_PERMISSION_FAULT_L0:
        case ARM64_DFSC_PERMISSION_FAULT_L1:
        case ARM64_DFSC_PERMISSION_FAULT_L2:
        case ARM64_DFSC_PERMISSION_FAULT_L3:
            pf_flags |= PF_FLAG_WRITE;
            break;
        default:
            eprintk("ARM64: unhandled DFSC on data abort: %s\n",
                    arm64_dfsc_to_string(dfsc));
            return IRQ_UNHANDLED;
    }

    res = vmem_map_handle_page_fault(
            (struct excp_state *)state,
            (void*)state->far,
            pf_flags,
            vmem_map_get_current());
    if(res) {
        return IRQ_UNHANDLED;
    }

    return IRQ_HANDLED;
}

static int
arm64_synchronous_exception(
        struct excp_state *gen_excp_state,
        struct irq_action *action)
{
    struct arm64_excp_state *state = (void*)gen_excp_state;
    uint64_t class = (state->esr >> 26) & 0x3F;
    uint64_t iss = (state->esr & 0xFFFFFF);
    switch(class) {
        case ARM64_ESR_EC_INST_ABORT_EL0:
            return arm64_handle_instruction_abort(state, action, 0, iss);
        case ARM64_ESR_EC_INST_ABORT_EL1:
            return arm64_handle_instruction_abort(state, action, 1, iss);
        case ARM64_ESR_EC_DATA_ABORT_EL0:
            return arm64_handle_data_abort(state, action, 0, iss);
        case ARM64_ESR_EC_DATA_ABORT_EL1:
            return arm64_handle_data_abort(state, action, 1, iss);
        case ARM64_ESR_EC_SVC_64:
            return arm64_handle_svc64(state, action, iss);
        default:
            wprintk("ARM64 Unhandled Synchronous Exception (Unhandled Exception Class 0x%lx \"%s\")!\n",
                    (ul_t)class,
                    arm64_esr_ec_to_string(class));
            return IRQ_UNHANDLED;
    }

    return IRQ_NONE;
}

static struct irq_action *sync_action = NULL;
static inline int
arm64_install_synchronous_exception_handler(void)
{
    irq_t irq = arm64_exception_irq(ARM64_EXCP_HWIRQ_SYNC);
    if(irq == NULL_IRQ) {
        return -EDEFER;
    }
    struct irq_desc *desc = irq_to_desc(irq);
    sync_action = irq_install_handler(
            desc,
            NULL,
            arm64_synchronous_exception);
    if(sync_action == NULL) {
        return -EDEFER;
    }
    return 0;
}
declare_init(dynamic, arm64_install_synchronous_exception_handler);
