
.global arm64_excp_vector_table

.p2align 11
arm64_excp_vector_table:
// EL1 with EL0 stack exceptions
.p2align 7
arm64_excp_el1_el0_stack_sync:
    b .
.p2align 7
arm64_excp_el1_el0_stack_irq:
    b .
.p2align 7
arm64_excp_el1_el0_stack_fiq:
    b .
.p2align 7
arm64_excp_el1_el0_stack_serror:
    b .

// EL1 with own stack exceptions
.p2align 7
arm64_excp_el1_sync:
    b .
.p2align 7
arm64_excp_el1_irq:
    b .
.p2align 7
arm64_excp_el1_fiq:
    b .
.p2align 7
arm64_excp_el1_serror:
    b .

// EL0 64-bit exceptions
.p2align 7
arm64_excp_el0_64_sync:
    b .
.p2align 7
arm64_excp_el0_64_irq:
    b .
.p2align 7
arm64_excp_el0_64_fiq:
    b .
.p2align 7
arm64_excp_el0_64_serror:
    b .

// EL0 32-bit exceptions
.p2align 7
arm64_excp_el0_32_sync:
    b .
.p2align 7
arm64_excp_el0_32_irq:
    b .
.p2align 7
arm64_excp_el0_32_fiq:
    b .
.p2align 7
arm64_excp_el0_32_serror:
    b .

