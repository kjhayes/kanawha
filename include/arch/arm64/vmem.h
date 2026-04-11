#ifndef __KANAWHA__ARM64_VMEM_H__
#define __KANAWHA__ARM64_VMEM_H__

#include <kanawha/assert.h>
#include <kanawha/pointer.h>
#include <kanawha/types.h>

#define VMEM_MIN_PAGE_ORDER 12

struct arch_vmem_map
{
    // TODO
};

struct arch_vmem_region
{
    // TODO
};

static inline void *
__va(void __phys *paddr)
{
    panic("__va called!\n");
    return NULL;
}

static inline void __phys *
__pa(void *vaddr)
{
    panic("__pa called!\n");
    return NULL;
}

#endif
