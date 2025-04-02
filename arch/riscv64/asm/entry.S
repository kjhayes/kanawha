
#include <arch/riscv64/mmu.h>

.extern __riscv64_kernel_load_addr

.extern riscv64_boot_bsp_init
.extern riscv64_virtual_bsp_init
.extern riscv64_boot_ap_init
.extern riscv64_virtual_ap_init

.option norvc
.option norelax

// We force .boot.init to be at the very base of the kernel image
.section .boot.init, "ax"

.global riscv64_kernel_entry
.type riscv64_kernel_entry, @function

    // Emulate the Linux RISCV boot header
riscv64_kernel_entry:
    j riscv64_kernel_boot
    j .
    .quad 0x0 /* Image load offset, little endian */
    .quad 0x0 /* Effective Image size, little endian */
    .long 0x0 /* kernel flags, little endian */
    .long 0x0 /* Version of this header */
    .long 0x0 /* Reserved */
    .quad 0x0 /* Reserved */
    .quad 0x5643534952 /* Magic number, little endian, "RISCV" */
    .long 0x05435352   /* Magic number 2, little endian, "RSC\x05" */
    .long 0x0 /* Reserved for PE COFF offset */

.section .boot.text, "ax"

.global riscv64_kernel_boot
.type riscv64_kernel_boot, @function

riscv64_kernel_boot:

    mv s7, a0 // Stash the hartid
    mv s8, a1 // Stash the device tree

    // Disable interrupts
    csrr t0, sstatus
    andi t0, t0, ~(1<<1)
    csrw sstatus, t0

    // Use the boot stack
    la sp, riscv64_boot_stack_base

    la s0, riscv64_have_booted_before
    ld s1, 0(s0)
    bne s1, zero, riscv64_reset_without_reload_panic

    // Mark that we have booted before
    li s1, 1
    sd s1, 0(s0)

    // Get the kernel loaded address 
.option push
.option norelax
    la a0, __riscv64_kernel_load_addr
.option pop   

    // Create and enable our boot page tables
    jal riscv64_boot_setup_paging

    // Our identity map base
    mv a3, a0

    // Get the kernel loaded address 
.option push
.option norelax
    la a0, __riscv64_kernel_load_addr
.option pop
    mv a2, s7 // Hart ID
    mv a1, s8 // Device Tree

    ld s0, riscv64_boot_bsp_init_ptr
    jalr s0

    // Virtualize the stack
    la s1, riscv64_boot_stack_base
    add sp, a0, s1

    ld s0, riscv64_virtual_bsp_init_ptr
    jalr s0

    // We should never reach here
    j .

riscv64_reset_without_reload_panic:
    j riscv64_reset_without_reload_panic

.global riscv64_ap_entry
.type riscv64_ap_entry, @function
riscv64_ap_entry:
    // a0 -> hartid
    // a1 -> satp

    csrw satp, a1

    // Use the boot stack
    la sp, riscv64_boot_stack_base

    ld a2, riscv64_boot_ap_init_ptr
    jalr a2

    // Load our new stack
    mv sp, a0

    ld a2, riscv64_virtual_ap_init_ptr
    jalr a2

    // We should never reach here
    j .

// Boot Page Tables
.section .boot.data, "aw"

.align 3
riscv64_have_booted_before:
.quad 0

.align 3
riscv64_global_ptr_ptr:
.quad __global_pointer$

.align 3
riscv64_boot_bsp_init_ptr:
.quad riscv64_boot_bsp_init

.align 3
riscv64_virtual_bsp_init_ptr:
.quad riscv64_virtual_bsp_init

.align 3
riscv64_boot_ap_init_ptr:
.quad riscv64_boot_ap_init

.align 3
riscv64_virtual_ap_init_ptr:
.quad riscv64_virtual_ap_init

// Boot Stack
.section .boot.data, "aw"
riscv64_boot_stack_top:
.fill CONFIG_RISCV64_BOOT_STACK_SIZE,1,0
riscv64_boot_stack_base:

