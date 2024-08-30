
#include <arch/x64/gdt.h>

/*
 * We may need to perform an IRET at the end of an interrupt,
 * in order to reset some state (NMI masking)
 * without actually returning from the interrupt, because
 * we may have done something such as switching threads.
 */

.macro NOP_IRET_STUB
    pushq %rax

    movq %rsp, %rax
    pushq $16  // Kernel Data Segment Selector (SS)
    pushq %rax // Stack to Restore
    pushfq     // RFLAGS to Restore
    pushq $8   // Kernel Code Segment Selector (CS)
    movabsq $.L0, %rax // Our Local Return Label (notice no $)
    pushq %rax

    iretq

.L0:
    popq %rax // Restore %rax

.endm

