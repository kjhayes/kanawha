
#include <arch/x64/gdt.h>

#ifdef CONFIG_X64_MULTIBOOT2_BOOT
.extern x64_multiboot2_entry
#endif

.global x64_boot_init
.global x64_bsp_init

.section .boot.text, "ax"

#if defined(CONFIG_X64_MULTIBOOT2_BOOT)
.code32
#else
#error "No Boot Method Found for x86_64!"
#endif

.global x64_kernel_entry
.type x64_kernel_entry, @function
x64_kernel_entry:
    movl $x64_boot_stack_base, %esp

#if defined(CONFIG_X64_MULTIBOOT2_BOOT)
  jmp x64_multiboot2_entry
#endif

// This is where all boot protocols should eventually land us
.code64
.global x64_common_entry
.type x64_common_entry, @function
x64_common_entry:

  // Interrupts should still be disabled, we might not
  // have an IDT yet.
  cli

  // Hardcode offset 16 into the GDT for the data segment (needs to change if the GDT is ever re-ordered)
  movw $0x10, %ax
  movw %ax, %ds
  movw %ax, %es
  movw %ax, %ss

  movw $0x0, %ax
  movw %ax, %fs
  movw %ax, %gs

  movq x64_boot_init_ptr, %rbp
  callq *%rbp

  // Virtualize the stack
  movq %rax, %rsp

  movq x64_bsp_init_ptr, %rbp
  callq *%rbp 

  // We should never reach here

__x64_common_entry_hlt_loop:
  cli
  hlt
  jmp __x64_common_entry_hlt_loop

.section .boot.data, "aw"
.global x64_boot_stack_base
x64_boot_stack_top:
.fill CONFIG_X64_BOOT_STACK_SIZE,1,0
x64_boot_stack_base:

x64_boot_init_ptr:
.quad x64_boot_bsp_init
x64_bsp_init_ptr:
.quad x64_bsp_init

