
#include <arch/riscv64/mmu.h>

.extern __riscv64_kernel_load_addr

.extern riscv64_boot_bsp_init

.option norvc
.option norelax

// Use Sv39 Page Tables for Booting
#ifdef CONFIG_RISCV64_SV39
#define RISCV64_BOOT_PAGE_TABLE_SATP_MODE (8<<60)
#define RISCV64_BOOT_PAGE_TABLE_VA_BITS 39
#define RISCV64_BOOT_PAGE_TABLE_PAGE_SIZE RISCV64_SV_PAGE_SIZE_LEVEL_2
#else
.err "CONFIG_RISCV64_SV39 is not set (current boot method depends on Sv39 support)!"
#endif

#define RISCV64_BOOT_HIGH_MEM_ROOT_INDEX\
    ((((1<<RISCV64_BOOT_PAGE_TABLE_VA_BITS)-1)&CONFIG_RISCV64_KERNEL_VIRTUAL_BASE)>>(RISCV64_BOOT_PAGE_TABLE_VA_BITS-9))

#define RISCV64_BOOT_NUM_2MB_PAGES\
    ((1<<CONFIG_RISCV64_BOOT_KERNEL_MAPPING_ORDER)>>21)
#define RISCV64_BOOT_NUM_2MB_PAGE_TABLES\
    ((RISCV64_BOOT_NUM_2MB_PAGES>>9)+1)

.if (RISCV64_BOOT_NUM_2MB_PAGE_TABLES+RISCV64_BOOT_HIGH_MEM_ROOT_INDEX)>RISCV64_SV_ENTRIES_PER_LEVEL
.err "CONFIG_RISCV64_BOOT_KERNEL_MAPPING_ORDER="CONFIG_RISCV64_BOOT_KERNEL_MAPPING_ORDER" is too large for Sv39!"
.endif

.if RISCV64_BOOT_HIGH_MEM_ROOT_INDEX == 0
.err "RISCV64_BOOT_HIGH_MEM_ROOT_INDEX="RISCV64_BOOT_HIGH_MEM_ROOT_INDEX" must not be zero!"
.endif

.section .boot.text, "ax"

.global riscv64_kernel_entry
.type riscv64_kernel_entry, @function

riscv64_kernel_entry:

    // Disable interrupts
    csrr t0, sstatus
    andi t0, t0, ~(1<<1)
    csrw sstatus, t0

    // Use the boot stack
    la sp, riscv64_boot_stack_base

    // Set up the root page table as an identity map for now
riscv64_boot_create_identity_mapping:
    li s0, 0
    li s1, RISCV64_SV_ENTRIES_PER_LEVEL
    la s2, riscv64_boot_page_table
    li s4, 0
    li s5, RISCV64_BOOT_PAGE_TABLE_PAGE_SIZE
riscv64_boot_create_identity_mapping_loop:
    li s3, (RISCV64_SV_VALID|RISCV64_SV_READ|RISCV64_SV_WRITE|RISCV64_SV_EXEC)
    srli s6, s4, 2 // I hate that the PPN is offset by 10 instead of 12 in the entry data structure
    or s3, s3, s6
    sd s3, 0(s2)
    addi s0, s0, 1
    addi s2, s2, 8
    add s4, s4, s5
    bne s0, s1, riscv64_boot_create_identity_mapping_loop

    // Enable Paging

    // Get the PPN of our page table for SATP
    la s2, riscv64_boot_page_table
    srli s2, s2, 12

    // Set the SATP Mode
    li s3, RISCV64_BOOT_PAGE_TABLE_SATP_MODE
    or s2, s2, s3

    csrw satp, s2

    // Create the high-mem virtual mapping from kernel virtual addresses to kernel physical addresses
    // using the 2MB page tables we statically allocated

riscv64_boot_create_virtual_mapping:
    la s6, __riscv64_kernel_load_addr
    srli s6, s6, 21 // 2MB PPN of the loaded physical base

    // Offset the physical address so we can just fill the 2mb page tables entirely
    li s5, ((CONFIG_RISCV64_KERNEL_VIRTUAL_BASE>>21) & 0x1FF) // Index into our 2MB entires to start mapping the kernel
    sub s6, s6, s5

    la s0, riscv64_boot_high_mem_page_tables
    li s1, 0
    li s2, RISCV64_BOOT_NUM_2MB_PAGE_TABLES*RISCV64_SV_ENTRIES_PER_LEVEL
riscv64_boot_create_virtual_mapping_loop:
    li s3, (RISCV64_SV_VALID|RISCV64_SV_READ|RISCV64_SV_WRITE|RISCV64_SV_EXEC)
    slli s5, s6, 19 // PPN is offset into the entry by 10 (then another 9 to offset by 2MB)
    or s3, s3, s5

    sd s3, 0(s0)

    addi s0, s0, 8
    addi s1, s1, 1
    addi s6, s6, 1
    bne s1, s2, riscv64_boot_create_virtual_mapping_loop

    // Our 2MB page tables should be filled out now
 
riscv64_boot_add_virtual_mapping:
    li s4, RISCV64_BOOT_HIGH_MEM_ROOT_INDEX
    slli s4, s4, 3 // Multiply by 8
    la s0, riscv64_boot_page_table
    add s0, s0, s4 // Compute the offset into the boot page table

    li s6, (RISCV64_SV_ENTRIES_PER_LEVEL*RISCV64_SV_ENTRY_DATA_SIZE) // Offset between 2MB page tables

    li s1, 0
    li s2, RISCV64_BOOT_NUM_2MB_PAGE_TABLES

    la s3, riscv64_boot_high_mem_page_tables

riscv64_boot_add_virtual_mapping_loop:

    srli s5, s3, 2
    ori s5, s5, 1

    sd s5, 0(s0)

    addi s1, s1, 1
    addi s0, s0, 8
    add s3, s3, s6
    bne s1, s2, riscv64_boot_add_virtual_mapping_loop

    // Flush the TLB
    sfence.vma

    la s0, riscv64_boot_bsp_init_ptr
    ld s0, 0(s0)
    jalr s0

    // We should never reach here
    j .

// Boot Page Tables
.section .boot.data, "aw"

.align 3
riscv64_global_ptr_ptr:
.quad __global_pointer$

.align 3
riscv64_boot_bsp_init_ptr:
.quad riscv64_boot_bsp_init

.align RISCV64_SV_TABLE_ALIGN
riscv64_boot_high_mem_page_tables:
.fill RISCV64_BOOT_NUM_2MB_PAGE_TABLES*RISCV64_SV_ENTRIES_PER_LEVEL,RISCV64_SV_ENTRY_DATA_SIZE,0
riscv64_boot_high_mem_page_tables_end:

.align RISCV64_SV_TABLE_ALIGN
riscv64_boot_page_table:
.fill RISCV64_SV_ENTRIES_PER_LEVEL,RISCV64_SV_ENTRY_DATA_SIZE,0
riscv64_boot_page_table_end:

// Boot Stack
.section .boot.data, "aw"
riscv64_boot_stack_base_addr:
.quad riscv64_boot_stack_base
riscv64_boot_stack_top:
.fill CONFIG_RISCV64_BOOT_STACK_SIZE,1,0
riscv64_boot_stack_base:

