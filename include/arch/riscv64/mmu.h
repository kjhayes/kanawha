#ifndef __KANAWHA__RISCV64_MMU_H__
#define __KANAWHA__RISCV64_MMU_H__

// This file should be includable from assembly and C source files

// SV -> Sv39 Sv48 or Sv57
#define RISCV64_SV_VALID (1ULL << 0)
#define RISCV64_SV_READ (1ULL << 1)
#define RISCV64_SV_WRITE (1ULL << 2)
#define RISCV64_SV_EXEC (1ULL << 3)
#define RISCV64_SV_USER (1ULL << 4)
#define RISCV64_SV_GLOBAL (1ULL << 5)
#define RISCV64_SV_ACCESSED (1ULL << 6)
#define RISCV64_SV_DIRTY (1ULL << 7)
#define RISCV64_SV_NAPOT (1ULL << 63)

#define RISCV64_SV_TABLE_ALIGN 12
#define RISCV64_SV_TABLE_ORDER 12

#define RISCV64_SV_ENTRY_DATA_SIZE 8ULL
#define RISCV64_SV_ENTRIES_PER_LEVEL 512ULL

#define RISCV64_SV_PAGE_ORDER_LEVEL_0 (12)
#define RISCV64_SV_PAGE_ORDER_LEVEL_1 (RISCV64_SV_PAGE_ORDER_LEVEL_0 + 9)
#define RISCV64_SV_PAGE_ORDER_LEVEL_2 (RISCV64_SV_PAGE_ORDER_LEVEL_1 + 9)
#define RISCV64_SV_PAGE_ORDER_LEVEL_3 (RISCV64_SV_PAGE_ORDER_LEVEL_2 + 9)
#define RISCV64_SV_PAGE_ORDER_LEVEL_4 (RISCV64_SV_PAGE_ORDER_LEVEL_3 + 9)

#define RISCV64_SV_PAGE_SIZE_LEVEL_0 (1ULL << 12)
#define RISCV64_SV_PAGE_SIZE_LEVEL_1 (RISCV64_SV_PAGE_SIZE_LEVEL_0 << 9)
#define RISCV64_SV_PAGE_SIZE_LEVEL_2 (RISCV64_SV_PAGE_SIZE_LEVEL_1 << 9)
#define RISCV64_SV_PAGE_SIZE_LEVEL_3 (RISCV64_SV_PAGE_SIZE_LEVEL_2 << 9)
#define RISCV64_SV_PAGE_SIZE_LEVEL_4 (RISCV64_SV_PAGE_SIZE_LEVEL_3 << 9)

#define RISCV64_SV_LEVEL_0_INDEX_ADDR_SHIFT (12)
#define RISCV64_SV_LEVEL_1_INDEX_ADDR_SHIFT                                    \
    (RISCV64_SV_LEVEL_0_INDEX_ADDR_SHIFT + 9)
#define RISCV64_SV_LEVEL_2_INDEX_ADDR_SHIFT                                    \
    (RISCV64_SV_LEVEL_1_INDEX_ADDR_SHIFT + 9)
#define RISCV64_SV_LEVEL_3_INDEX_ADDR_SHIFT                                    \
    (RISCV64_SV_LEVEL_2_INDEX_ADDR_SHIFT + 9)
#define RISCV64_SV_LEVEL_4_INDEX_ADDR_SHIFT                                    \
    (RISCV64_SV_LEVEL_3_INDEX_ADDR_SHIFT + 9)

#define RISCV64_SV_LEVEL_0_INDEX_OF_ADDR(addr)                                 \
    (((addr) >> RISCV64_SV_LEVEL_0_INDEX_ADDR_SHIFT) &                         \
     (RISCV64_SV_ENTRIES_PER_LEVEL - 1))
#define RISCV64_SV_LEVEL_1_INDEX_OF_ADDR(addr)                                 \
    (((addr) >> RISCV64_SV_LEVEL_1_INDEX_ADDR_SHIFT) &                         \
     (RISCV64_SV_ENTRIES_PER_LEVEL - 1))
#define RISCV64_SV_LEVEL_2_INDEX_OF_ADDR(addr)                                 \
    (((addr) >> RISCV64_SV_LEVEL_2_INDEX_ADDR_SHIFT) &                         \
     (RISCV64_SV_ENTRIES_PER_LEVEL - 1))
#define RISCV64_SV_LEVEL_3_INDEX_OF_ADDR(addr)                                 \
    (((addr) >> RISCV64_SV_LEVEL_3_INDEX_ADDR_SHIFT) &                         \
     (RISCV64_SV_ENTRIES_PER_LEVEL - 1))
#define RISCV64_SV_LEVEL_4_INDEX_OF_ADDR(addr)                                 \
    (((addr) >> RISCV64_SV_LEVEL_4_INDEX_ADDR_SHIFT) &                         \
     (RISCV64_SV_ENTRIES_PER_LEVEL - 1))

#define RISCV64_SV_ENTRY_IS_LEAF(entry)                                        \
    ((entry & (RISCV64_SV_READ | RISCV64_SV_EXEC)) != 0)

#define RISCV64_SV39_NUM_LEVELS 3
#define RISCV64_SV48_NUM_LEVELS 4
#define RISCV64_SV57_NUM_LEVELS 5

// Kanawha Custom Fields
#define RISCV64_SV_VMEM_SHARED_MAP (1ULL << 8)

#ifndef __ASSEMBLER__

#include <kanawha/pointer.h>
#include <kanawha/printk.h>
#include <kanawha/types.h>

struct __attribute__((aligned(1 << RISCV64_SV_TABLE_ALIGN), packed))
riscv64_sv_page_table
{
    uint64_t entries[RISCV64_SV_ENTRIES_PER_LEVEL];
};

static inline void
riscv64_flush_tlb(void)
{
    asm volatile("sfence.vma");
}

static inline uint64_t
riscv64_format_satp(void __phys *root_table, int root_level)
{
    uint64_t satp_value = ((uintptr_t)root_table >> 12);

    switch(root_level)
    {
    case 2:
        satp_value |= (8ULL << 60);
        break;
    case 3:
        satp_value |= (9ULL << 60);
        break;
    case 4:
        satp_value |= (10ULL << 60);
        break;
    default:
        panic("Trying to format an invalid SATP value!\n");
    }
    return satp_value;
}

#endif

#endif
