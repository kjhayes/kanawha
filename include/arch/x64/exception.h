#ifndef __KANAWHA__ARCH_X64_EXCEPTION_H__
#define __KANAWHA__ARCH_X64_EXCEPTION_H__

#define X64_NUM_EXCP 32

#define X64_EXCP_TYPE_FAULT 0
#define X64_EXCP_TYPE_TRAP  1
#define X64_EXCP_TYPE_ABORT 2
#define X64_EXCP_TYPE_MIXED 3
#define X64_EXCP_TYPE_INTR  4
#define X64_EXCP_TYPE_UNDEF 5

// (vector, mnemonic, desc_str, has_errcode, type, ...)
#define X64_EXCP_XLIST(X)\
    X(0,  DE,    "Divide-by-Zero",             0, X64_EXCP_TYPE_FAULT)\
    X(1,  DB,    "Debug",                      0, X64_EXCP_TYPE_MIXED)\
    X(2,  NMI,   "Non-Maskable-Interrupt",     0, X64_EXCP_TYPE_INTR)\
    X(3,  BP,    "Breakpoint",                 0, X64_EXCP_TYPE_TRAP)\
    X(4,  OF,    "Overflow",                   0, X64_EXCP_TYPE_TRAP)\
    X(5,  BR,    "Bound-Range",                0, X64_EXCP_TYPE_FAULT)\
    X(6,  UD,    "Invalid-Opcode",             0, X64_EXCP_TYPE_FAULT)\
    X(7,  NM,    "Device-Not-Available",       0, X64_EXCP_TYPE_FAULT)\
    X(8,  DF,    "Double-Fault",               1, X64_EXCP_TYPE_ABORT)\
    X(9,  RESV,  "Reserved",                   0, X64_EXCP_TYPE_UNDEF)\
    X(10, TS,    "Invalid-TSS",                1, X64_EXCP_TYPE_FAULT)\
    X(11, NP,    "Segment-Not-Present",        1, X64_EXCP_TYPE_FAULT)\
    X(12, SS,    "Stack",                      1, X64_EXCP_TYPE_FAULT)\
    X(13, GP,    "General-Protection",         1, X64_EXCP_TYPE_FAULT)\
    X(14, PF,    "Page-Fault",                 1, X64_EXCP_TYPE_FAULT)\
    X(15, RESV,  "Reserved",                   0, X64_EXCP_TYPE_UNDEF)\
    X(16, MF,    "x87-Floating-Point-Pending", 0, X64_EXCP_TYPE_FAULT)\
    X(17, AC,    "Alignment-Check",            1, X64_EXCP_TYPE_FAULT)\
    X(18, MC,    "Machine-Check",              0, X64_EXCP_TYPE_ABORT)\
    X(19, XF,    "SIMD-Floating-Point",        0, X64_EXCP_TYPE_FAULT)\
    X(20, RESV,  "Reserved",                   0, X64_EXCP_TYPE_UNDEF)\
    X(21, RESV,  "Reserved",                   0, X64_EXCP_TYPE_UNDEF)\
    X(22, RESV,  "Reserved",                   0, X64_EXCP_TYPE_UNDEF)\
    X(23, RESV,  "Reserved",                   0, X64_EXCP_TYPE_UNDEF)\
    X(24, RESV,  "Reserved",                   0, X64_EXCP_TYPE_UNDEF)\
    X(25, RESV,  "Reserved",                   0, X64_EXCP_TYPE_UNDEF)\
    X(26, RESV,  "Reserved",                   0, X64_EXCP_TYPE_UNDEF)\
    X(27, RESV,  "Reserved",                   0, X64_EXCP_TYPE_UNDEF)\
    X(28, RESV,  "Reserved",                   0, X64_EXCP_TYPE_UNDEF)\
    X(29, RESV,  "Reserved",                   0, X64_EXCP_TYPE_UNDEF)\
    X(30, SX,    "Security",                   0, X64_EXCP_TYPE_INTR)\
    X(31, RESV,  "Reserved",                   0, X64_EXCP_TYPE_UNDEF)

#ifndef __ASSEMBLER__

#include <kanawha/stdint.h>
#include <arch/x64/asm/regs.S>
#include <kanawha/irq_domain.h>

extern struct irq_domain *x64_vector_irq_domain;

static inline irq_t
x64_vector_irq(hwirq_t vector) {
    if(x64_vector_irq_domain == NULL) {
        return NULL_IRQ;
    }
    return irq_domain_revmap(x64_vector_irq_domain, vector);
}

static inline struct irq_desc *
x64_vector_irq_desc(hwirq_t vector)
{
    irq_t irq = x64_vector_irq(vector);
    if(irq == NULL_IRQ) {
        return NULL;
    }
    return irq_to_desc(irq);
}

// Look for an IRQ vector which we can use,
// with as few actions as possible already attached
irq_t x64_request_irq_vector(void);

// Same as x64_request_irq_vector but the interrupt
// will only be signalled on "cpu"
irq_t x64_request_cpu_irq_vector(cpu_id_t cpu);

void
x64_nop_iret(void);

struct
x64_excp_state
{
    union {
        uint8_t caller_regs_raw[CALLER_PUSH_SIZE];
    } __caller_regs;

    uint64_t vector;
    uint64_t error_code;
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
} __attribute__((packed));

__attribute__((noreturn)) void
x64_unhandled_exception(struct x64_excp_state *state);

#endif

#endif
