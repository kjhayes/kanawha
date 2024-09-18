
#include "./static_page_table.S"

.extern x64_bsp_gdt64
.extern x64_bsp_tss_data
.extern x64_prot_mode_idtr

#include<arch/x64/gdt.h>

.section .boot.text, "ax"

#define VBASE_PT_OFFSET CONFIG_VIRTUAL_BASE & (X64_PT_ENTRY_REGION_SIZE-1)
#define VBASE_PD_OFFSET CONFIG_VIRTUAL_BASE & (X64_PD_ENTRY_REGION_SIZE-1)
#define VBASE_PDPT_OFFSET CONFIG_VIRTUAL_BASE & (X64_PDPT_ENTRY_REGION_SIZE-1)

#if CONFIG_IDENTITY_MAP_ORDER > 21
    #define IDENT_MAP_PT_TABLES_ORDER   (CONFIG_IDENTITY_MAP_ORDER - 21)
#else
    #define IDENT_MAP_PT_TABLES_ORDER 0
#endif

#if CONFIG_IDENTITY_MAP_ORDER > 30
    #define IDENT_MAP_PD_TABLES_ORDER   (CONFIG_IDENTITY_MAP_ORDER - 30)
#else
    #define IDENT_MAP_PD_TABLES_ORDER 0
#endif

#if CONFIG_IDENTITY_MAP_ORDER > 39
    #define IDENT_MAP_PDPT_TABLES_ORDER (CONFIG_IDENTITY_MAP_ORDER - 39)
#else
    #define IDENT_MAP_PDPT_TABLES_ORDER 0
#endif

#define IDENT_MAP_PT_TABLES   (1<<IDENT_MAP_PT_TABLES_ORDER)
#define IDENT_MAP_PD_TABLES   (1<<IDENT_MAP_PD_TABLES_ORDER)
#define IDENT_MAP_PDPT_TABLES (1<<IDENT_MAP_PDPT_TABLES_ORDER)

.if IDENT_MAP_PDPT_TABLES > X64_PML4_ENTRIES
.err "CONFIG_IDENTITY_MAP_ORDER = "CONFIG_IDENTITY_MAP_ORDER" cannot fit within a single PML4 table!"
.endif

.code32

.global x64_prot_to_long_mode
.type x64_prot_to_long_mode, @function
x64_prot_to_long_mode:
    // Just to be safe
    cli

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
    movl $x64_prot_to_long_pdpt_array, %esi
    orl $X64_PML4_ENTRY_PRESENT, %esi
    orl $X64_PML4_ENTRY_WRITE, %esi

    // little endian, we only overwrite the low 32 bits of the entry but that's fine
    movl $0, %edi
    movl %esi, 0(%eax,%edi,8)

    // Now map in the virtual address of the kernel
    movl $x64_prot_to_long_pdpt_array, %esi
    orl $X64_PML4_ENTRY_PRESENT, %esi
    orl $X64_PML4_ENTRY_WRITE, %esi

    movl $(X64_PML4_INDEX_OF_ADDR(CONFIG_VIRTUAL_BASE)), %edi
    movl %esi, 0(%eax,%edi,8)

#ifdef CONFIG_X64_ASSUME_1GB_PAGES

    // Fill the PDPT array with 1GB page mappings

__x64_prot_to_long_fill_pdpt_array:
    movl $0, %edi // edi -> entry index
    movl $(X64_PDPT_ENTRIES * IDENT_MAP_PDPT_TABLES), %esi // esi -> sentinel
    movl $x64_prot_to_long_pdpt_array, %ebx // ebx -> base of pdpt array
__x64_prot_to_long_fill_pdpt_loop:

    movl %edi, %eax
    movl $(X64_PDPT_ENTRY_REGION_SIZE), %edx
    mull %edx
    // Stores result of (%eax * %edx) into %edx:%eax

    orl $(X64_PDPT_ENTRY_PAGE_SIZE|X64_PDPT_ENTRY_PRESENT|X64_PDPT_ENTRY_WRITE), %eax
    movl %eax, 0(%ebx, %edi, 8)
    movl %edx, 4(%ebx, %edi, 8)

    incl %edi
    cmpl %esi, %edi
    jb __x64_prot_to_long_fill_pdpt_loop

#else

    // Fill the PDPT array with mappings to the PD array

__x64_prot_to_long_fill_pdpt_array:
    movl $0, %edi // edi -> entry index
    movl $(IDENT_MAP_PD_TABLES), %esi // esi -> sentinel
    movl $x64_prot_to_long_pdpt_array, %ebx // ebx -> base of pdpt array
__x64_prot_to_long_fill_pdpt_loop:

    movl %edi, %eax
    movl $(X64_PD_SIZE), %edx
    mull %edx
    // Stores result of (%eax * %edx) into %edx:%eax

    // edx should realistically be 0x0 right now,
    // and eax should not overflow from this
    //
    // (Technically not sure at this point though, hence the check)
    addl $x64_prot_to_long_pd_array, %eax
    jo __x64_prot_to_long_overflow

    orl $(X64_PDPT_ENTRY_PRESENT|X64_PDPT_ENTRY_WRITE), %eax
    movl %eax, 0(%ebx, %edi, 8)
    movl %edx, 4(%ebx, %edi, 8)

    incl %edi
    cmpl %esi, %edi
    jb __x64_prot_to_long_fill_pdpt_loop

#ifdef CONFIG_X64_ASSUME_2MB_PAGES

    // Fill the PD array with 2MB page mappings

__x64_prot_to_long_fill_pd_array:
    movl $0, %edi // edi -> entry index
    movl $(X64_PD_ENTRIES * IDENT_MAP_PD_TABLES), %esi // esi -> sentinel
    movl $x64_prot_to_long_pd_array, %ebx // ebx -> base of pd array
__x64_prot_to_long_fill_pd_loop:

    movl %edi, %eax
    movl $(X64_PD_ENTRY_REGION_SIZE), %edx
    mull %edx
    // Stores result of (%eax * %edx) into %edx:%eax

    orl $(X64_PD_ENTRY_PAGE_SIZE|X64_PD_ENTRY_PRESENT|X64_PD_ENTRY_WRITE), %eax
    movl %eax, 0(%ebx, %edi, 8)
    movl %edx, 4(%ebx, %edi, 8)

    incl %edi
    cmpl %esi, %edi
    jb __x64_prot_to_long_fill_pd_loop

#else
#error "NO"
#endif

#endif

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


__x64_prot_to_long_overflow:
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
x64_prot_to_long_pdpt_array:
.fill X64_PDPT_SIZE,IDENT_MAP_PDPT_TABLES,0
#ifndef CONFIG_X64_ASSUME_1GB_PAGES
.align (1<<X64_PD_ALIGN)
x64_prot_to_long_pd_array:
.fill X64_PD_SIZE,IDENT_MAP_PD_TABLES,0
#ifndef CONFIG_X64_ASSUME_2MB_PAGES
.align (1<<X64_PT_ALIGN)
x64_prot_to_long_pt_array:
.fill X64_PT_SIZE,IDENT_MAP_PT_TABLES,0
#endif
#endif

.if VBASE_PDPT_OFFSET == 0
.else
.err "CONFIG_VIRTUAL_BASE="CONFIG_VIRTUAL_BASE" is not aligned to the same position in the a PDPT Page as physical address 0 (VBASE_PDPT_OFFSET="VBASE_PDPT_OFFSET")!"
.endif

.if VBASE_PD_OFFSET == 0
.else
.err "CONFIG_VIRTUAL_BASE="CONFIG_VIRTUAL_BASE" is not aligned to the same position in the a PD Page as physical address 0 (VBASE_PD_OFFSET="VBASE_PD_OFFSET")!"
.endif

.if VBASE_PT_OFFSET == 0
.else
.err "CONFIG_VIRTUAL_BASE="CONFIG_VIRTUAL_BASE" is not aligned to the same position in the a PT Page as physical address 0 (VBASE_PT_OFFSET="VBASE_PD_OFFSET")!"
.endif

.if X64_PML4_ADDR_IS_CANONICAL(CONFIG_VIRTUAL_BASE)
.else
.err "CONFIG_VIRTUAL_BASE="CONFIG_VIRTUAL_BASE" is non-canonical for 4-level paging!"
.endif

