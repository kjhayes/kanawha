
.global __arm64_enter_usermode
.type __arm64_enter_usermode,@function
__arm64_enter_usermode:
    // x0 -> void __user *starting_address
    // x1 -> void *arg
    // x2 -> void *sp_el1

    // Reset the kernel stack
    mov sp, x2

    // Set ELR_EL1 to "return" us to "starting_address"
    msr ELR_EL1, x0

    // Setup SPSR for usermode
    mov x0, 0
    msr SPSR_EL1, x0

    // Move our argument into x0
    mov x0, x1

    // Clear other registers for entry
    mov x1, 0
    mov x2, 0
    mov x3, 0
    mov x4, 0
    mov x5, 0
    mov x6, 0
    mov x7, 0
    mov x8, 0
    mov x9, 0
    mov x10, 0
    mov x11, 0
    mov x12, 0
    mov x13, 0
    mov x14, 0
    mov x15, 0
    mov x16, 0
    mov x17, 0
    mov x18, 0
    mov x19, 0
    mov x20, 0
    mov x21, 0
    mov x22, 0
    mov x23, 0
    mov x24, 0
    mov x25, 0
    mov x26, 0
    mov x27, 0
    mov x28, 0
    mov x29, 0
    mov x30, 0

    // Return to userspace
    eret
