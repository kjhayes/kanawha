
#include <kanawha/mmap.h>
#include <kanawha/sys-wrappers.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MINIMUM_ALLOCATION_SIZE (16)
#define HEAP_BLOCK_SIZE (0x100000)
#define HEAP_MMAP_SIZE (0x1000)

struct heap_block
{
    struct heap_block *next;
    unsigned long size;
    struct free_region *free_list;
    uint8_t data[];
};

struct free_region
{
    unsigned long data_size;
    struct free_region *next;
    uint8_t data[];
};
struct allocation
{
    unsigned long data_size;
    struct allocation *self;
    uint8_t data[];
};

_Static_assert(sizeof(struct free_region) == sizeof(struct allocation),
               "Kanawha LibC freelist allocator depends on sizeof(struct "
               "free_region) == sizeof(struct allocation)!");

static unsigned int heap_lock = 0;
static inline void
heap_lock_acquire(void)
{
    while(__sync_fetch_and_or(&heap_lock, 1))
    {
    }
}
static inline void
heap_lock_release(void)
{
    heap_lock = 0;
}
static struct heap_block *heap_block_list = NULL;

static struct heap_block *
heap_grow_lockless(void)
{
    int res;
    void *new_block;
    res = kanawha_sys_mmap(0,
                           0,
                           &new_block,
                           HEAP_BLOCK_SIZE,
                           MMAP_ANON | MMAP_PROT_READ | MMAP_PROT_WRITE);
    if(res)
    {
        return NULL;
    }
    struct heap_block *block = new_block;

    block->size = HEAP_BLOCK_SIZE;

    struct free_region *init_free = (void *)block->data;
    init_free->next = NULL;
    init_free->data_size =
        block->size - sizeof(struct free_region) - sizeof(struct heap_block);
    block->free_list = init_free;

    // Insert into the block list
    block->next = heap_block_list;
    heap_block_list = block;

    return block;
}

void *
malloc(size_t size)
{
    // Round all allocations up to 16 bytes
    // (This ensures alignment as well)
    if(size == 0)
    {
        return NULL;
    }
    {
        size_t rem = size % MINIMUM_ALLOCATION_SIZE;
        if(rem)
        {
            size += (MINIMUM_ALLOCATION_SIZE - rem);
        }
    }

    if(size >= HEAP_MMAP_SIZE)
    {
        int res;
        void *alloc;

        // Round up to the nearest page
        size += HEAP_MMAP_SIZE - 1;
        size &= ~(HEAP_MMAP_SIZE - 1);

        res = kanawha_sys_mmap(0,
                               0,
                               &alloc,
                               size,
                               MMAP_ANON | MMAP_PROT_WRITE | MMAP_PROT_READ);
        if(res)
        {
            return NULL;
        }
        return alloc;
    }

    heap_lock_acquire();
    struct heap_block *blk_iter = heap_block_list;
    while(blk_iter)
    {
        struct free_region **slot = &blk_iter->free_list;
        struct free_region *region = blk_iter->free_list;

        struct allocation *alloc = NULL;
        while(region)
        {
            if(region->data_size == size)
            {
                *slot = region->next;
                struct allocation *alloc = (void *)region;
                break;
            }
            else if(region->data_size > (size + sizeof(struct allocation)))
            {
                region->data_size -= (size + sizeof(struct allocation));
                alloc = (void *)(region->data + region->data_size);
                break;
            }

            // Move on to the next free region
            slot = &region->next;
            region = region->next;
        }

        // We searched the entire free list and found nothing
        if(alloc == NULL)
        {
            blk_iter = blk_iter->next;
            continue;
        }

        alloc->data_size = size;
        alloc->self = (void *)alloc;
        heap_lock_release();
        return alloc->data;
    }

    heap_grow_lockless();
    heap_lock_release();
    return malloc(size); // Recursion!
                         // Maybe a bad idea but ANY
                         // decent compiler should tail
                         // call optimize this...
                         // Also this is userspace so who
                         // really cares...
}

void
free(void *ptr)
{
    if(ptr == NULL)
    {
        return;
    }

    heap_lock_acquire();
    struct heap_block *block = NULL;
    struct heap_block *blk_iter = heap_block_list;
    while(blk_iter)
    {
        if((ptr >= (void *)blk_iter) &&
           (ptr < ((void *)blk_iter + blk_iter->size)))
        {
            block = blk_iter;
            break;
        }
        blk_iter = blk_iter->next;
    }
    if(block == NULL)
    {
        // This must have been an mmap allocation.
        heap_lock_release();
        int res;
        res = kanawha_sys_munmap(ptr);
        if(res)
        {
            // Huh? (TODO: Log a warning somehow?)
        }
        return;
    }

    struct allocation *alloc = ptr - sizeof(struct allocation);
    if(alloc->self != (void *)alloc)
    {
        // This is not a valid heap allocation, or a
        // heap corruption has occurred.
        printf("PID(%u) free-ing invalid address (%p)!\n",
               (unsigned int)getpid(),
               ptr);
        abort();
    }

    unsigned long data_size = alloc->data_size;
    struct free_region *free = (void *)alloc;
    free->data_size = data_size;

    // Push this onto the front of the list
    // TODO: Search for adjacent blocks and merge.
    free->next = block->free_list;
    block->free_list = free;

    heap_lock_release();
}
