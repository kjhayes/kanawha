
.extern arm64_boot_bsp_init

.section .boot.text, "ax"

.global arm64_kernel_entry
.type arm64_kernel_entry, @function
arm64_kernel_entry:

#ifdef CONFIG_ARM64_BOOT_BAREMETAL
    ldr x0, =ARM64_BAREMETAL_BOOT_DEVICE_TREE_PHYS_ADDR
#endif

    // Disable interrupts
    msr DAIFSet, 0b1111

    // Save the device tree pointer
    mov x20, x0

    // Load the boot stack
    ldr x0, =arm64_boot_stack_base
    mov sp, x0

    // We need to set up paging ASAP
    bl arm64_boot_setup_paging

    mov x0, x20
    ldr x1, =arm64_boot_bsp_init
    blr x1 

arm64_kernel_entry_error_loop:
    b .

.section .boot.data, "aw"

arm64_boot_stack_top:
.fill CONFIG_ARM64_BOOT_STACK_SIZE,1,0
arm64_boot_stack_base:

