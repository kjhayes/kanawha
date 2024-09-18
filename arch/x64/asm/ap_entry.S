
.global x64_ap_init

#define AP_TRAMPOLINE_STACK_SIZE 128

// We have no gaurentees on where this code is actually placed
// within our real-mode address space, everything needs to be relative

.extern x64_prot_to_long_mode
.extern x64_boot_stack_base

.global x64_ap_trampoline_start
.global x64_ap_trampoline_end

.global x64_ap_trampoline_ap_launched_byte
.global x64_ap_trampoline_self_ptr
.global x64_ap_trampoline_virtual_stack_base

// We need a fixed physical address we can make the jump to
// flat addressing with
.section .boot.text, "ax"

.code32
x64_ap_entry_common_prot_mode: 
     // %edi and %esi should already be set with the bits of our return address
     xorl %edx, %edx // zero means we are an AP
     jmp x64_prot_to_long_mode

.code64
.global x64_ap_common_entry
.type x64_ap_common_entry, @function
x64_ap_common_entry:

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

__x64_ap_common_entry_stacked:
  movq x64_ap_boot_init_ptr, %rbp
  callq *%rbp 

  // We should never reach here

.section .boot.data, "aw"
x64_ap_boot_init_ptr:
.quad x64_boot_ap_init

.section .rodata

.align 0x1000
.org 0x0
x64_ap_trampoline_start:

.code16
.global x64_ap_entry
.type x64_ap_entry, @function
x64_ap_entry:

    cli

    movw %cs, %ax
    movw %ax, %ds

    // Let the BSP know that we are running
    movb $1, %ds:(x64_ap_trampoline_ap_launched_byte-x64_ap_trampoline_start)

    // Get an absolute pointer to the trampoline page
    movw %ds:(x64_ap_trampoline_self_ptr-x64_ap_trampoline_start), %bx

    // We need to get to protected mode,
    // but then we can use the same protected -> long mode
    // setup code as the BSP

    // First fix-up our realmode GDT
    movl %ebx, %eax
    addl $(x64_ap_trampoline_realmode_gdt-x64_ap_trampoline_start), %eax
    movl %eax, %ds:(x64_ap_trampoline_realmode_gdtr_gdt_addr-x64_ap_trampoline_start)

    // Patch our "relative" CS segment
    movl %ebx, %eax
    movl $(x64_ap_trampoline_realmode_gdt_relative_cs-x64_ap_trampoline_start), %edx
    addl $2, %edx

    // Low word of our base (we have to be in the bottom 64 KiB so this is enough)
    movw %ax, %ds:(%edx)

    // Load the GDT
    lgdtl %ds:(x64_ap_trampoline_realmode_gdtr-x64_ap_trampoline_start)

    // Enable Protected Mode
    movl    %cr0, %eax
    orl     $1, %eax
    movl    %eax, %cr0

    // Long Jump to protected mode (CS may still not be flat though)
    ljmp $0x8, $(x64_ap_trampoline_prot_entry-x64_ap_trampoline_start)

.align 32
.code32
x64_ap_trampoline_prot_entry:

    // Long Jump to reload CS with a flat map and start running our protected -> long mode transition

    // Address which x64_prot_to_long_mode will jump to
    movl $(x64_ap_trampoline_long_mode_entry-x64_ap_trampoline_start), %edi // Low half of first long mode address
    addl %ebx, %edi
    xorl %esi, %esi // High half of address must be zeros

    // Start Flat Addressing Data
    movw $0x18, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    ljmp $0x10, $(x64_ap_entry_common_prot_mode)

.code16
    .align 16
x64_ap_trampoline_realmode_gdt:
    .long 0, 0                    //null descriptor
x64_ap_trampoline_realmode_gdt_relative_cs:
    .long 0x0000FFFF, 0x00CF9A00  //relative code (needs to be patched)
    .long 0x0000FFFF, 0x00CF9A00  //flat code
    .long 0x0000FFFF, 0x008F9200  //flat data
    .long 0x00000068, 0x00CF8900  //tss
x64_ap_trampoline_realmode_gdt_end:
x64_ap_trampoline_realmode_gdtr:
    .word x64_ap_trampoline_realmode_gdt_end - x64_ap_trampoline_realmode_gdt - 1
x64_ap_trampoline_realmode_gdtr_gdt_addr:
    .long 0
    .long 0, 0

.align 16
.code64
x64_ap_trampoline_long_mode_entry:

    // In long mode we can finally do a %rip relative load isntead of needing the
    // trampoline_self_ptr

    movq x64_ap_trampoline_virtual_stack_base(%rip), %rax
    andq $(~0xF), %rax
    movq %rax, %rsp

    leaq x64_ap_common_entry, %rbp
    jmp *%rbp

.code16
x64_ap_trampoline_ap_launched_byte:
.byte 0x0
x64_ap_trampoline_self_ptr:
.byte 0, 0
x64_ap_trampoline_virtual_stack_base:
.quad 0

x64_ap_trampoline_end:

