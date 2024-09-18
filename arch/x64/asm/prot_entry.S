
#include "./static_page_table.S"

.extern x64_bsp_gdt64
.extern x64_bsp_tss_data
.extern x64_prot_mode_idtr

#include<arch/x64/gdt.h>

.section .boot.text, "ax"

#define VBASE_PT_OFFSET CONFIG_VIRTUAL_BASE & (X64_PT_ENTRY_REGION_SIZE-1)
#define VBASE_PD_OFFSET CONFIG_VIRTUAL_BASE & (X64_PD_ENTRY_REGION_SIZE-1)
#define VBASE_PDPT_OFFSET CONFIG_VIRTUAL_BASE & (X64_PDPT_ENTRY_REGION_SIZE-1)

#define PBASE_PT_OFFSET CONFIG_KERNEL_LOAD_ADDR & (X64_PT_ENTRY_REGION_SIZE-1)
#define PBASE_PD_OFFSET CONFIG_KERNEL_LOAD_ADDR & (X64_PD_ENTRY_REGION_SIZE-1)
#define PBASE_PDPT_OFFSET CONFIG_KERNEL_LOAD_ADDR & (X64_PDPT_ENTRY_REGION_SIZE-1)

.code32

.global x64_prot_to_long_mode
.type x64_prot_to_long_mode, @function
x64_prot_to_long_mode:
    // Just to be safe
    cli

//    lidt (x64_prot_mode_idtr)

    // %edi is the low-bits of the address to jump to in 64-bit code
    movl %edi, x64_prot_to_long_first_addr_low
    // %esi is the high-bits of the address to jump to in 64-bit code
    movl %esi, x64_prot_to_long_first_addr_high

    // %edx: 0 -> AP 1 -> BSP
    test %edx, %edx
    jz __x64_prot_to_long_ap_skip_page_table_setup

__x64_prot_to_long_page_table_setup:
    // Set up page tables
    movl $x64_prot_to_long_pml4, %eax

    // Start off mapping in the physical memory region of the kernel 1-to-1
    movl $x64_prot_to_long_low_pdpt, %esi
    orl $X64_PML4_ENTRY_PRESENT, %esi
    orl $X64_PML4_ENTRY_WRITE, %esi

    // little endian, we only overwrite the low 32 bits of the entry but that's fine
    movl $(X64_PML4_INDEX_OF_ADDR(CONFIG_KERNEL_LOAD_ADDR)), %edi
    movl %esi, 0(%eax,%edi,8)

    // Now map in the virtual address of the kernel
    movl $x64_prot_to_long_high_pdpt, %esi
    orl $X64_PML4_ENTRY_PRESENT, %esi
    orl $X64_PML4_ENTRY_WRITE, %esi

    movl $(X64_PML4_INDEX_OF_ADDR(CONFIG_VIRTUAL_BASE)), %edi
    movl %esi, 0(%eax,%edi,8)

__x64_prot_to_long_detect_cpuid:

    // Make sure that we can flip the CPUID bit in the FLAGS register
    pushfl
    popl %eax
    mov %ecx, %eax
    xor $(1<<21), %eax
    pushl %eax
    popfl

    pushfl
    popl %eax

    pushl %ecx
    popfl

    cmp %eax, %ecx
    jz __x64_prot_to_long_no_cpuid

__x64_prot_to_long_detect_ext_cpuid_feat:

    // Make sure that the CPUID 0x80000001 exists (if it doesn't long mode can't exist)
    movl $0x80000000, %eax
    cpuid
    cmpl $0x80000001, %eax
    jb __x64_prot_to_long_no_ext_cpuid_feat

__x64_prot_to_long_detect_long_mode:

    // Check that long mode is supported
    movl $0x80000001, %eax
    cpuid
    testl $(1<<29), %edx
    jz __x64_prot_to_long_no_long_mode

__x64_prot_to_long_check_pml:
    movl %cr4, %edx
    testl $(1<<12), %edx
    jnz __x64_prot_to_long_pml5_enabled

__x64_prot_to_long_ap_skip_page_table_setup:
    // Enable PAE
    movl %cr4, %ebx
    orl $(1<<5), %ebx
    movl %ebx, %cr4

    // Set Long-Mode-Enable in the EFER MSR
    movl $0xC0000080, %ecx
    rdmsr
    orl $(1<<8), %eax
    wrmsr

__x64_prot_to_long_paging_enable:
    movl $x64_prot_to_long_pml4, %eax
    movl %eax, %cr3

    // Enable Paging
    movl %cr0, %eax
    orl  $(1 << 31), %eax
    movl %eax, %cr0

    movl $0xB8000, %edx
    movb $'$',  0(%edx)
    movb $0xCA, 1(%edx)
    jmp .

    // Set the TSS Segment Base (Would be nice to get the compiler/linker to do this for us)

__x64_prot_to_long_tss_setup:
    // Point %esi at our TSS segment descriptor
    // Skip over the first three descriptors (CHANGE THIS IF THE STATIC GDT LAYOUT CHANGES)
    movl $((x64_bsp_gdt64 - CONFIG_VIRTUAL_BASE)), %esi
    addl $24, %esi

    movl $x64_prot_to_long_tss_data_ptr, %edi
    movl 0(%edi), %eax

    // Write bits 0-15
    movw %ax, 0x2(%esi)

    // Write bits 16-23
    shrl $16, %eax
    movb %al, 0x4(%esi)

    // Write bits 24-31
    movb %ah, 0x7(%esi)

    // Write bits 32-63
    movl 4(%edi), %eax
    movl %eax, 0x8(%esi)

__x64_prot_to_long_load_gdt:
    // Load the GDT
    movl $x64_prot_to_long_gdtr64, %eax
    lgdt 0(%eax)

    // %edx: 0 -> AP 1 -> BSP
    test %edx, %edx
    jz __x64_prot_to_long_ap_skip_load_tss

    mov $0x18, %ax
    ltr %ax

__x64_prot_to_long_ap_skip_load_tss:
    // Hardcoded to offset 8 into the GDT (needs to change if the GDT is ever re-ordered)
    ljmp $0x8, $x64_prot_to_long_begin_long_mode

.code64
.type x64_prot_to_long_begin_long_mode, @function
x64_prot_to_long_begin_long_mode:
    cli

    movq x64_prot_to_long_first_addr, %rax
    jmpq *%rax

    // We should never get here
__x64_prot_to_long_hlt_loop:
    cli
    hlt
    jmp __x64_prot_to_long_hlt_loop


__x64_prot_to_long_no_cpuid:
__x64_prot_to_long_no_ext_cpuid_feat:
__x64_prot_to_long_no_long_mode:
__x64_prot_to_long_pml5_enabled:
    jmp __x64_prot_to_long_hlt_loop

.section .boot.data, "aw"

x64_prot_to_long_first_addr:
x64_prot_to_long_first_addr_low:
.byte 0,0,0,0
x64_prot_to_long_first_addr_high:
.byte 0,0,0,0

x64_prot_to_long_gdtr64:
.short ((X64_GDT64_SIZE) - 1)
.quad (x64_bsp_gdt64 - CONFIG_VIRTUAL_BASE)

x64_prot_to_long_tss_data_ptr:
.quad x64_bsp_tss_data 

.align (1<<X64_PML4_ALIGN)
x64_prot_to_long_pml4:
.fill X64_PML4_SIZE,1,0

.align (1<<X64_PDPT_ALIGN)
x64_prot_to_long_low_pdpt:
DECLARE_PDPT_LEAF_MAPPING base_paddr=(CONFIG_KERNEL_LOAD_ADDR-PBASE_PDPT_OFFSET),entries=X64_PDPT_ENTRIES

.align (1<<X64_PDPT_ALIGN)
x64_prot_to_long_high_pdpt:
DECLARE_PDPT_LEAF_MAPPING base_paddr=(CONFIG_KERNEL_LOAD_ADDR-PBASE_PDPT_OFFSET),entries=X64_PDPT_ENTRIES

.if VBASE_PDPT_OFFSET == 0
.else
.err "CONFIG_VIRTUAL_BASE="CONFIG_VIRTUAL_BASE" is not aligned to the same position in the a PDPT Page as physical address 0 (VBASE_PDPT_OFFSET="VBASE_PDPT_OFFSET")!"
.endif

.if X64_PML4_ADDR_IS_CANONICAL(CONFIG_VIRTUAL_BASE)
.else
.err "CONFIG_VIRTUAL_BASE="CONFIG_VIRTUAL_BASE" is non-canonical for 4-level paging!"
.endif

