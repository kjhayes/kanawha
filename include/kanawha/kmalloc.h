#ifndef __KANAWHA__KMALLOC_H__
#define __KANAWHA__KMALLOC_H__

#include <kanawha/string.h>
#include <kanawha/types.h>

#define KMALLOC_ALIGN_ORDER 4

// Default, no flags
#define KM_KERNEL  (0)
// Allocation should not out-live the thread which allocated it
#define KM_THREAD  (1UL<<0)

// size is both an input and an output,
// but as an output it must be >= the input value
void *
kmalloc_specific(order_t align_order, size_t *size);
int
kfree_specific(void *addr, order_t align_order, size_t size);

// Wrappers on the k*_specific functions that assume a maximum alignment
// for the architecture and track the size internally
void *
kmalloc(size_t size, unsigned long flags);
void
kfree(void *addr);

// Same as kmalloc but zeros the memory on success
#define kzmalloc(size, flags)                                                  \
    ({                                                                         \
        void *alloc = kmalloc(size, flags);                                    \
        if(alloc != NULL)                                                      \
        {                                                                      \
            memset(alloc, 0, size);                                            \
        }                                                                      \
        alloc;                                                                 \
    })

#endif
