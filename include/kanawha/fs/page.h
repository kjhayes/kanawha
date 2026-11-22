#ifndef __KANAWHA__FS_PAGE_H__
#define __KANAWHA__FS_PAGE_H__

#include <kanawha/types.h>
#include <kanawha/pointer.h>
#include <kanawha/pcache.h>

#define FS_PAGE_FLAG_DIRTY (1UL << 0)
struct fs_page
{
    void __phys *paddr;
    order_t order;

    unsigned long flags;

    struct pcache_node cache_node;
};

#endif
