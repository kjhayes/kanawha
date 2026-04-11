
.section .boot.text, "ax"

.global arm64_kernel_entry
.type arm64_kernel_entry, @function
arm64_kernel_entry:

    // Disable interrupts
    msr DAIFSet, 0b1111

    // Save the device tree pointer
    mov x20, x0

    // Load the boot stack
    ldr x0, =arm64_boot_stack_base
    mov sp, x0

    // We need to set up paging ASAP
    b .

arm64_kernel_entry_error_loop:
    b .

.section .boot.data, "aw"

arm64_boot_stack_top:
.fill CONFIG_ARM64_BOOT_STACK_SIZE,1,0
arm64_boot_stack_base:

