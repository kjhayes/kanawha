
#include <arch/arm64/mmu.h>

#define ARM64_BOOT_NUM_L1_LOW_TABLES 1
#define ARM64_BOOT_NUM_L1_HIGH_TABLES 1

#define ARM64_BOOT_PAGING_NUM_SLAB_TABLES (32)
#define ARM64_BOOT_PAGING_SLAB_SIZE (0x1000 * ARM64_BOOT_PAGING_NUM_SLAB_TABLES)

.section .boot.data, "aw"

arm64_boot_paging_root_table_low:
.fill 0x1000,1,0
arm64_boot_paging_root_table_high:
.fill 0x1000,1,0

arm64_boot_paging_slab_offset:
.quad 0
arm64_boot_paging_slab_start:
.fill ARM64_BOOT_PAGING_SLAB_SIZE,1,0
arm64_boot_paging_slab_end:

.section .boot.text, "ax"

.type arm64_boot_setup_paging, @function
arm64_boot_paging_slab_alloc:
// x0 -> order
   adr x1, arm64_boot_paging_slab_offset
   ldr x1, [x1]

   // Align x1 up to the order in x0 (uses x2 as scratch)
   mov x2, 1
   lsl x2, x2, x0
   sub x2, x2, 1
   neg x2, x2
   add x1, x1, x2
   and x1, x1, x2

   // Save our offset value in x0
   mov x0, x1

   // Move the slab buffer again
   neg x2, x2
   add x2, x2, 1
   add x1, x2, x2

   // Make sure x1 didn't overrun the slab buffer
   cmp x1, ARM64_BOOT_PAGING_SLAB_SIZE
   b.gt arm64_boot_paging_slab_out_of_memory
 
   // Save the new offset
   adr x2, arm64_boot_paging_slab_offset
   str x1, [x2]

   // Now compute the actual pointer
   adr x1, arm64_boot_paging_slab_start
   add x0, x0, x1

   ret

arm64_boot_paging_slab_out_of_memory:
   b .

.type arm64_boot_paging_drill, @function
arm64_boot_paging_drill:
   // Args
   // x0 (x19) -> page table
   // x1 (x20) -> desired level
   // x2 (x21) -> virtual pointer
   // x3 (x22) -> physical pointer

   sub sp, sp, 0x50
   stp x19, x20, [sp, 0x00] 
   stp x21, x22, [sp, 0x10] 
   stp x23, x24, [sp, 0x20] 
   stp x25, x26, [sp, 0x30] 
   stp x27, x30, [sp, 0x40] 

   mov x19, x0
   mov x20, x1
   mov x21, x2
   mov x22, x3
   
   // Locals
   // x23 -> current level
   mov x23, 0
arm64_boot_paging_drill_loop:

   // Determine what shift/mask to index the table we need
   // x24 -> shift
   // x25 -> mask
   // x26 -> table_order 
   // x27 -> entry_ptr 
   mov x24, 0
   mov x25, 0

   mov x0, ARM64_V48G4_L0_INDEX_SHIFT
   mov x1, ARM64_V48G4_L0_INDEX_MASK
   mov x2, ARM64_V48G4_L0_TABLE_SIZE_ORDER
   cmp x23, 0
   csel x24, x0, x24, EQ 
   csel x25, x1, x25, EQ 
   csel x26, x2, x26, EQ 

   mov x0, ARM64_V48G4_L1_INDEX_SHIFT
   mov x1, ARM64_V48G4_L1_INDEX_MASK
   mov x2, ARM64_V48G4_L1_TABLE_SIZE_ORDER
   cmp x23, 1
   csel x24, x0, x24, EQ 
   csel x25, x1, x25, EQ 
   csel x26, x2, x26, EQ 

   mov x0, ARM64_V48G4_L2_INDEX_SHIFT
   mov x1, ARM64_V48G4_L2_INDEX_MASK
   mov x2, ARM64_V48G4_L2_TABLE_SIZE_ORDER
   cmp x23, 2
   csel x24, x0, x24, EQ 
   csel x25, x1, x25, EQ 
   csel x26, x2, x26, EQ 

   mov x0, ARM64_V48G4_L3_INDEX_SHIFT
   mov x1, ARM64_V48G4_L3_INDEX_MASK
   mov x2, ARM64_V48G4_L3_TABLE_SIZE_ORDER
   cmp x23, 3
   csel x24, x0, x24, EQ 
   csel x25, x1, x25, EQ 
   csel x26, x2, x26, EQ 

   lsr x27, x21, x24
   and x27, x27, x25
   // x27 should now contain our index
  
   lsl x27, x27, ARM64_PAGETABLE_ENTRY_SIZE_ORDER
   // x27 should now contain our offset
  
   add x27, x27, x19
   // x27 should now contain a pointer to the current entry

   cmp x23, x20 // current_level == desired level?
   b.eq arm64_boot_paging_drill_correct_level

   // Check if the table exists
   ldr x25, [x27]
   and x25, x25, 3
   cmp x25, 3
   b.eq arm64_boot_paging_drill_table_exists
 
   // We need to allocate the table
   mov x0, x26
   bl arm64_boot_paging_slab_alloc

   // We need to create a new table entry
   orr x0, x0, 3
   str x0, [x27]

arm64_boot_paging_drill_table_exists:
   // Descend a level (increasing)
   ldr x27, [x27]

   and x19, x27, 0x0000FFFFFFFFF000 // Mask address portion
   add x23, x23, 1

   b arm64_boot_paging_drill_loop
arm64_boot_paging_drill_correct_level:

   // leaf vs. block entry
   mov x0, 3
   mov x1, 1
   cmp x23, 3
   csel x0, x0, x1, EQ
   
   // Put the bottom bits on our physical address
   orr x22, x22, x0

   orr x22, x22, (1<<10) // Set the "access" flag
   
   // Store the entry
   str x22, [x27]

   ldp x19, x20, [sp, 0x00]
   ldp x21, x22, [sp, 0x10]
   ldp x23, x24, [sp, 0x20]
   ldp x25, x26, [sp, 0x30]
   ldp x27, x30, [sp, 0x40]
   add sp, sp, 0x50

   ret

.type arm64_boot_setup_paging, @function
arm64_boot_map_region:
   // x0 (x19) -> virtual address
   // x1 (x20) -> physical address
   // x2 (x21) -> size

   sub sp, sp, 0x40
   stp x19, x20, [sp, 0x00]
   stp x21, x22, [sp, 0x10]
   stp x23, x24, [sp, 0x20]
   stp x25, x30, [sp, 0x30]

   // x23 will be the root table

   mov x19, x0
   mov x20, x1
   mov x21, x2

   mov x1, 0xFFFF000000000000
   and x0, x19, x1
   cbz x0, arm64_boot_map_region_low_mem_addr
   cmp x0, x1
   b.eq arm64_boot_map_region_high_mem_addr

arm64_boot_map_region_non_canon_virt_error:
   b .

arm64_boot_map_region_low_mem_addr:
   adr x23, arm64_boot_paging_root_table_low
   b arm64_boot_map_region_loop
arm64_boot_map_region_high_mem_addr:
   adr x23, arm64_boot_paging_root_table_high
   b arm64_boot_map_region_loop

arm64_boot_map_region_loop:
   mov x22, 1 // desired level
   mov x24, ARM64_V48G4_L1_ENTRY_REGION
   and x0, x19, ((1<<ARM64_V48G4_L1_INDEX_SHIFT)-1)
   and x1, x20, ((1<<ARM64_V48G4_L1_INDEX_SHIFT)-1)
   and x2, x21, ((1<<ARM64_V48G4_L1_INDEX_SHIFT)-1)
   orr x0, x0, x1
   orr x0, x0, x2
   cbz x0, arm64_boot_map_region_found_order

   mov x22, 2 // desired level
   mov x24, ARM64_V48G4_L2_ENTRY_REGION
   and x0, x19, ((1<<ARM64_V48G4_L2_INDEX_SHIFT)-1)
   and x1, x20, ((1<<ARM64_V48G4_L2_INDEX_SHIFT)-1)
   and x2, x21, ((1<<ARM64_V48G4_L2_INDEX_SHIFT)-1)
   orr x0, x0, x1
   orr x0, x0, x2
   cbz x0, arm64_boot_map_region_found_order

   mov x22, 3 // desired level
   mov x24, ARM64_V48G4_L3_ENTRY_REGION
   and x0, x19, ((1<<ARM64_V48G4_L3_INDEX_SHIFT)-1)
   and x1, x20, ((1<<ARM64_V48G4_L3_INDEX_SHIFT)-1)
   and x2, x21, ((1<<ARM64_V48G4_L3_INDEX_SHIFT)-1)
   orr x0, x0, x1
   orr x0, x0, x2
   cbz x0, arm64_boot_map_region_found_order

arm64_boot_map_region_misaligned_error:
   b .

arm64_boot_map_region_found_order:
   // x22 -> desired level

   mov x0, x23 // root table
   mov x1, x22 // desired level
   mov x2, x19 // virtual
   mov x3, x20 // physical
   bl arm64_boot_paging_drill

   add x19, x19, x24
   add x20, x20, x24
   sub x21, x21, x24

   cbnz x21, arm64_boot_map_region_loop

   ldp x19, x20, [sp, 0x00]
   ldp x21, x22, [sp, 0x10]
   ldp x23, x24, [sp, 0x20]
   ldp x25, x30, [sp, 0x30]
   add sp, sp, 0x40

   ret

arm64_boot_map_region_error:
   b .

.global arm64_boot_setup_paging
.type arm64_boot_setup_paging, @function
arm64_boot_setup_paging:

    sub sp, sp, 0x10
    stp x19, x30, [sp, 0x00]
    
    mov x19, x0

    // Identity map the low 64GiB
    mov x0, 0x0
    mov x1, 0x0
    mov x2, (1<<CONFIG_ARM64_BOOT_LOWMEM_IDENTITY_MAP_ORDER)
    bl arm64_boot_map_region

    ldr x0, =CONFIG_ARM64_KERNEL_VIRTUAL_BASE
    ldr x1, =CONFIG_ARM64_LINKED_PHYS_BASE
    sub x0, x0, x1
    mov x1, 0
    mov x2, (1<<CONFIG_ARM64_BOOT_HIGHMEM_KERNEL_MAP_ORDER)
    bl arm64_boot_map_region

    // Set Root Table Addresses
    adr x0, arm64_boot_paging_root_table_low
    msr TTBR0_EL1, x0
    adr x0, arm64_boot_paging_root_table_high
    msr TTBR1_EL1, x0

    // Configure Paging
    mov x0, 0
    orr x0, x0, ((64-48)<<0) // Set low memory to use 48-bit virtual addresses
    // orr x0, x0, (0<<14) // Use 4KB granule in low memory
    orr x0, x0, ((64-48)<<16) // Set high memory to use 48-bit virtual addresses
    orr x0, x0, (2<<30) // Use 4KB granule in high memory

    orr x0, x0, (1<<32) // Use 48-bit physical addresses
    orr x0, x0, (1<<34) 
    msr TCR_EL1, x0

    // Enable Paging
    mrs x0, SCTLR_EL1
    orr x0, x0, (1<<0)  // MMU Enable
    orr x0, x0, (1<<12) // I-Cache Enable
    msr SCTLR_EL1, x0

    ldp x19, x30, [sp, 0x00]
    add sp, sp, 0x10

    ret

arm64_boot_setup_paging_error_loop:
    b .

