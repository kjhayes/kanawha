#ifndef __KANAWHA__ARCH_X64_VIRT_MEM_H__
#define __KANAWHA__ARCH_X64_VIRT_MEM_H__

#include <kanawha/stdint.h>

#define VMEM_MIN_PAGE_ORDER 12

struct arch_vmem_map 
{
    paddr_t pt_root;
    int pt_level;
};

struct arch_vmem_region 
{
    paddr_t pt_table;
    int pt_level;

    uint64_t pt_entry;
    int entry_only;
};

#endif
