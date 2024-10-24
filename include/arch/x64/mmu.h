#ifndef __KANAWHA__X64_MMU_H__
#define __KANAWHA__X64_MMU_H__

#define X64_PML5_SIZE    4096ULL
#define X64_PML5_ENTRIES 512ULL
#define X64_PML5_ALIGN   12ULL
#define X64_PML5_ENTRY_REGION_SIZE (X64_PML4_ENTRY_REGION_SIZE*X64_PML4_ENTRIES)
#define X64_PML4_SIZE    4096ULL
#define X64_PML4_ENTRIES 512ULL
#define X64_PML4_ALIGN   12ULL
#define X64_PML4_ENTRY_REGION_SIZE (X64_PDPT_ENTRY_REGION_SIZE*X64_PDPT_ENTRIES)
#define X64_PDPT_SIZE    4096ULL
#define X64_PDPT_ENTRIES 512ULL
#define X64_PDPT_ALIGN   12ULL
#define X64_PDPT_ENTRY_REGION_SIZE (X64_PD_ENTRY_REGION_SIZE*X64_PD_ENTRIES)
#define X64_PD_SIZE      4096ULL
#define X64_PD_ENTRIES   512ULL
#define X64_PD_ALIGN     12ULL
#define X64_PD_ENTRY_REGION_SIZE (X64_PT_ENTRY_REGION_SIZE*X64_PT_ENTRIES)
#define X64_PT_SIZE      4096ULL
#define X64_PT_ENTRIES   512ULL
#define X64_PT_ALIGN     12ULL
#define X64_PT_ENTRY_REGION_SIZE 4096

#define X64_PT_INDEX_ADDR_SHIFT 12
#define X64_PD_INDEX_ADDR_SHIFT 21
#define X64_PDPT_INDEX_ADDR_SHIFT 30
#define X64_PML4_INDEX_ADDR_SHIFT 39
#define X64_PML5_INDEX_ADDR_SHIFT 48

#define X64_PML5_INDEX_OF_ADDR(addr) ((addr>>X64_PML5_INDEX_ADDR_SHIFT)&(X64_PML5_ENTRIES-1))
#define X64_PML4_INDEX_OF_ADDR(addr) ((addr>>X64_PML4_INDEX_ADDR_SHIFT)&(X64_PML4_ENTRIES-1))
#define X64_PDPT_INDEX_OF_ADDR(addr) ((addr>>X64_PDPT_INDEX_ADDR_SHIFT)&(X64_PDPT_ENTRIES-1))
#define X64_PD_INDEX_OF_ADDR(addr)   ((addr>>X64_PD_INDEX_ADDR_SHIFT)&(X64_PD_ENTRIES-1))
#define X64_PT_INDEX_OF_ADDR(addr)   ((addr>>X64_PT_INDEX_ADDR_SHIFT)&(X64_PT_ENTRIES-1))

#define X64_PML5_ENTRY_PRESENT              (1ULL<<0)
#define X64_PML5_ENTRY_WRITE                (1ULL<<1)
#define X64_PML5_ENTRY_USER                 (1ULL<<2)
#define X64_PML5_ENTRY_WRITE_THROUGH        (1ULL<<3)
#define X64_PML5_ENTRY_CACHE_DISABLE        (1ULL<<4)
#define X64_PML5_ENTRY_ACCESSED             (1ULL<<5)
#define X64_PML5_ENTRY_PAGE_SIZE            (1ULL<<7)
#define X64_PML5_ENTRY_EXEC_DISABLE         (1ULL<<63)
#define X64_PML5_ENTRY_ADDR_MASK            0x000FFFFFFFFFF000

#define X64_PML4_LOWMEM_SIZE (1ULL<<47)
#define X64_PML4_HIGHMEM_SIZE (1ULL<<47)
#define X64_PML4_HIGHMEM_BASE (-X64_PML4_HIGHMEM_SIZE)

#define X64_PML5_LOWMEM_SIZE (1ULL<<56)
#define X64_PML5_HIGHMEM_SIZE (1ULL<<56)
#define X64_PML5_HIGHMEM_BASE (-X64_PML5_HIGHMEM_SIZE)

#define X64_PML5_ADDR_IS_CANONICAL(addr) (((addr & 0xFF80000000000000) == 0) || ((addr & 0xFF80000000000000) == 0xFF80000000000000))

#define X64_PML4_ENTRY_PRESENT              (1ULL<<0)
#define X64_PML4_ENTRY_WRITE                (1ULL<<1)
#define X64_PML4_ENTRY_USER                 (1ULL<<2)
#define X64_PML4_ENTRY_WRITE_THROUGH        (1ULL<<3)
#define X64_PML4_ENTRY_CACHE_DISABLE        (1ULL<<4)
#define X64_PML4_ENTRY_ACCESSED             (1ULL<<5)
#define X64_PML4_ENTRY_PAGE_SIZE            (1ULL<<7)
#define X64_PML4_ENTRY_EXEC_DISABLE         (1ULL<<63)
#define X64_PML4_ENTRY_ADDR_MASK            0x000FFFFFFFFFF000

#define X64_PML4_ADDR_IS_CANONICAL(addr) (((addr & 0xFFFF800000000000) == 0) || ((addr & 0xFFFF800000000000) == 0xFFFF800000000000))

#define X64_PDPT_ENTRY_PRESENT              (1ULL<<0)
#define X64_PDPT_ENTRY_WRITE                (1ULL<<1)
#define X64_PDPT_ENTRY_USER                 (1ULL<<2)
#define X64_PDPT_ENTRY_WRITE_THROUGH        (1ULL<<3)
#define X64_PDPT_ENTRY_CACHE_DISABLE        (1ULL<<4)
#define X64_PDPT_ENTRY_ACCESSED             (1ULL<<5)
#define X64_PDPT_ENTRY_PAGE_SIZE            (1ULL<<7)
#define X64_PDPT_ENTRY_EXEC_DISABLE         (1ULL<<63)
#define X64_PDPT_ENTRY_ADDR_MASK            0x000FFFFFFFFFF000

#define X64_PD_ENTRY_PRESENT              (1ULL<<0)
#define X64_PD_ENTRY_WRITE                (1ULL<<1)
#define X64_PD_ENTRY_USER                 (1ULL<<2)
#define X64_PD_ENTRY_WRITE_THROUGH        (1ULL<<3)
#define X64_PD_ENTRY_CACHE_DISABLE        (1ULL<<4)
#define X64_PD_ENTRY_ACCESSED             (1ULL<<5)
#define X64_PD_ENTRY_PAGE_SIZE            (1ULL<<7)
#define X64_PD_ENTRY_EXEC_DISABLE         (1ULL<<63)
#define X64_PD_ENTRY_ADDR_MASK            0x000FFFFFFFFFF000

#define X64_PDPT_LEAF_PRESENT              (1ULL<<0)
#define X64_PDPT_LEAF_WRITE                (1ULL<<1)
#define X64_PDPT_LEAF_USER                 (1ULL<<2)
#define X64_PDPT_LEAF_WRITE_THROUGH        (1ULL<<3)
#define X64_PDPT_LEAF_CACHE_DISABLE        (1ULL<<4)
#define X64_PDPT_LEAF_ACCESSED             (1ULL<<5)
#define X64_PDPT_LEAF_DIRTY                (1ULL<<6)
#define X64_PDPT_LEAF_PAGE_SIZE            (1ULL<<7)
#define X64_PDPT_LEAF_GLOBAL               (1ULL<<8)
#define X64_PDPT_LEAF_PAGE_ATTRIBUTE_TABLE (1ULL<<9)
#define X64_PDPT_LEAF_EXEC_DISABLE         (1ULL<<63)
#define X64_PDPT_LEAF_ADDR_MASK            0x000FFFFFC0000000

#define X64_PD_LEAF_PRESENT              (1ULL<<0)
#define X64_PD_LEAF_WRITE                (1ULL<<1)
#define X64_PD_LEAF_USER                 (1ULL<<2)
#define X64_PD_LEAF_WRITE_THROUGH        (1ULL<<3)
#define X64_PD_LEAF_CACHE_DISABLE        (1ULL<<4)
#define X64_PD_LEAF_ACCESSED             (1ULL<<5)
#define X64_PD_LEAF_DIRTY                (1ULL<<6)
#define X64_PD_LEAF_PAGE_SIZE            (1ULL<<7)
#define X64_PD_LEAF_GLOBAL               (1ULL<<8)
#define X64_PD_LEAF_PAGE_ATTRIBUTE_TABLE (1ULL<<9)
#define X64_PD_LEAF_EXEC_DISABLE         (1ULL<<63)
#define X64_PD_LEAF_ADDR_MASK            0x000FFFFFFFE00000

#define X64_PT_LEAF_PRESENT              (1ULL<<0)
#define X64_PT_LEAF_WRITE                (1ULL<<1)
#define X64_PT_LEAF_USER                 (1ULL<<2)
#define X64_PT_LEAF_WRITE_THROUGH        (1ULL<<3)
#define X64_PT_LEAF_CACHE_DISABLE        (1ULL<<4)
#define X64_PT_LEAF_ACCESSED             (1ULL<<5)
#define X64_PT_LEAF_DIRTY                (1ULL<<6)
#define X64_PT_LEAF_PAGE_ATTRIBUTE_TABLE (1ULL<<7)
#define X64_PT_LEAF_GLOBAL               (1ULL<<8)
#define X64_PT_LEAF_EXEC_DISABLE         (1ULL<<63)
#define X64_PT_LEAF_ADDR_MASK            0x000FFFFFFFFFF000

// Kanawha Custom Fields

// Uses the available bit 9 to keep track if this page table
// is owned by a vmem_map or a vmem_region (1=map, 0=region)
#define X64_PD_ENTRY_VMEM_SHARED_MAP     (1ULL<<9)
#define X64_PDPT_ENTRY_VMEM_SHARED_MAP     (1ULL<<9)
#define X64_PML4_ENTRY_VMEM_SHARED_MAP     (1ULL<<9)
#define X64_PML5_ENTRY_VMEM_SHARED_MAP     (1ULL<<9)

#endif
