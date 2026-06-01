
.extern arm64_boot_bsp_init
.extern arm64_virtual_bsp_init
.extern arm64_excp_vector_table

.section .boot.text, "ax"

.global arm64_kernel_entry
.type arm64_kernel_entry, @function
arm64_kernel_entry:

#ifdef CONFIG_ARM64_BAREMETAL_BOOT
    ldr x0, =CONFIG_ARM64_BAREMETAL_BOOT_DEVICE_TREE_PHYS_ADDR
#endif

    // Disable interrupts
    msr DAIFSet, 0b1111

    // Save the device tree pointer
    mov x20, x0

    // Set SPSel to always use the EL1 stack
    mov x0, 1
    msr SPSel, x0

    // Load the boot stack
    ldr x0, =arm64_boot_stack_base
    mov sp, x0

    // We need to set up paging ASAP
    bl arm64_boot_setup_paging

    mov x0, x20
    ldr x1, =arm64_boot_bsp_init
    blr x1 

    // Setup virtual exception vectors
    ldr x0, =arm64_excp_vector_table
    msr VBAR_EL1,x0

    // Switch to the virtual stack
    ldr x0, =arm64_virt_boot_stack_base
    mov sp, x0

    ldr x1, =arm64_virtual_bsp_init
    br x1 
    // No link, we can never return...

arm64_kernel_entry_error_loop:
    b .

.section .boot.data, "aw"

arm64_boot_stack_top:
.fill CONFIG_ARM64_BOOT_STACK_SIZE,1,0
arm64_boot_stack_base:

.section .data, "aw"
arm64_virt_boot_stack_top:
.fill CONFIG_ARM64_BOOT_STACK_SIZE,1,0
arm64_virt_boot_stack_base:

