#ifndef __KANAWHA__ARM64_EXCP_H__
#define __KANAWHA__ARM64_EXCP_H__

#define ARM64_EXCP_HWIRQ_SYNC   (0)
#define ARM64_EXCP_HWIRQ_IRQ    (1)
#define ARM64_EXCP_HWIRQ_FIQ    (2)
#define ARM64_EXCP_HWIRQ_SERROR (3)

#define ARM64_EXCP_FLAG_USER  (1UL<<0)
#define ARM64_EXCP_FLAG_32BIT (1UL<<1)

#ifndef __ASSEMBLER__
#include <arch/arm64/asm/regs.h>
#include <kanawha/attribute.h>
#include <kanawha/types.h>
#include <kanawha/irq_domain.h>

struct __packed arm64_excp_state {
    uint64_t spsr;
    uint64_t elr;
    uint64_t esr;
    uint64_t far;
    uint64_t callee_regs[ARM64_THREAD_CALLEE_PUSH_SIZE/8];
    uint64_t caller_regs[ARM64_THREAD_CALLER_PUSH_SIZE/8];
    uint64_t hwirq;
    uint64_t flags;
};

irq_t arm64_exception_irq(hwirq_t hwirq);

#define ARM64_ESR_EC_XLIST(X,...)\
X(UNKNOWN,        0b000000, ##__VA_ARGS__)\
X(WF_INST,        0b000001, ##__VA_ARGS__)\
X(MCR_MRC_1111,   0b000011, ##__VA_ARGS__)\
X(MCRR_MRRC,      0b000100, ##__VA_ARGS__)\
X(MCR_MRC_1110,   0b000101, ##__VA_ARGS__)\
X(LDC_STC,        0b000110, ##__VA_ARGS__)\
X(SVE_FPEN,       0b000111, ##__VA_ARGS__)\
X(ST64B_LD64B,    0b001010, ##__VA_ARGS__)\
X(MRRC_1110,      0b001100, ##__VA_ARGS__)\
X(BRANCH_TARGET,  0b001101, ##__VA_ARGS__)\
X(ILL_EXEC_STATE, 0b001110, ##__VA_ARGS__)\
X(SVC_32,         0b010001, ##__VA_ARGS__)\
X(SVC_64,         0b010101, ##__VA_ARGS__)\
X(MSR_MRS_64,     0b011000, ##__VA_ARGS__)\
X(SVE_ZEN,        0b011001, ##__VA_ARGS__)\
X(POINTER_AUTH,   0b011100, ##__VA_ARGS__)\
X(INST_ABORT_EL0, 0b100000, ##__VA_ARGS__)\
X(INST_ABORT_EL1, 0b100001, ##__VA_ARGS__)\
X(PC_ALIGN,       0b100010, ##__VA_ARGS__)\
X(DATA_ABORT_EL0, 0b100100, ##__VA_ARGS__)\
X(DATA_ABORT_EL1, 0b100101, ##__VA_ARGS__)\
X(SP_ALIGN,       0b100110, ##__VA_ARGS__)\
X(FP_32,          0b101000, ##__VA_ARGS__)\
X(FP_64,          0b101100, ##__VA_ARGS__)\
X(SERROR,         0b101111, ##__VA_ARGS__)\
X(BREAKPOINT_EL0, 0b110000, ##__VA_ARGS__)\
X(BREAKPOINT_EL1, 0b110001, ##__VA_ARGS__)\
X(STEP_EL0,       0b110010, ##__VA_ARGS__)\
X(STEP_EL1,       0b110011, ##__VA_ARGS__)\
X(WATCHPOINT_EL0, 0b110100, ##__VA_ARGS__)\
X(WATCHPOINT_EL1, 0b110101, ##__VA_ARGS__)\
X(BKPT_32,        0b111000, ##__VA_ARGS__)\
X(BRK_64,         0b111100, ##__VA_ARGS__)

enum {
#define ARM64_ESR_EC_DECLARE_ENUM(__NAME, __VALUE, ...)\
    ARM64_ESR_EC_ ## __NAME = __VALUE,
ARM64_ESR_EC_XLIST(ARM64_ESR_EC_DECLARE_ENUM)
#undef ARM64_ESR_EC_DECLARE_ENUM
};

static inline const char *
arm64_esr_ec_to_string(unsigned long value)
{
    switch(value) {
#define ARM64_ESR_EC_DECLARE_TO_STRING_CASE(__NAME, __VALUE, ...)\
        case ARM64_ESR_EC_ ## __NAME: return #__NAME;
ARM64_ESR_EC_XLIST(ARM64_ESR_EC_DECLARE_TO_STRING_CASE)
#undef ARM64_ESR_EC_DECLARE_TO_STRING_CASE
        default: return "INVALID";
    }
}

#endif
#endif
