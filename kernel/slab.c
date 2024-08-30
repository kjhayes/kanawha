
#include <kanawha/slab.h>
#include <kanawha/stdint.h>
#include <kanawha/stddef.h>
#include <kanawha/errno.h>
#include <kanawha/bitmap.h>
#include <kanawha/string.h>
#include <kanawha/page_alloc.h>
#include <kanawha/mem_flags.h>
#include <kanawha/vmem.h>

#define SLAB_ALLOC_BLOCK_PAGE_ORDER PAGE_ALLOC_MIN_ORDER

static void
init_slab_allocator(
        struct slab_allocator *alloc,
        size_t obj_size,
        order_t obj_align)
{
    ilist_init(&alloc->block_list);
    alloc->obj_size = obj_size;
    alloc->obj_align = obj_align;
}

static int
slab_allocator_add_block(
        struct slab_allocator *alloc,
        void *block_base,
        size_t block_size,
        unsigned long flags)
{
    size_t overhead = sizeof(struct slab_alloc_block);
    ssize_t useful_mem = block_size - overhead;
    
    struct slab_alloc_block *block = block_base;

    // Align the struct correctly
    {
    size_t mis_align = ((uintptr_t)block % alignof(struct slab_alloc_block));
    size_t patch = mis_align == 0 ? 0 : alignof(struct slab_alloc_block)-mis_align;
    overhead += patch;
    useful_mem -= patch;
    block = ((void*)block) + patch;
    }

    if(useful_mem <= 0) {
        // The block is definitely too small to be useful
        return -EINVAL;
    }

    block->block_base = block_base;
    block->block_size = block_size;
    block->flags = flags;

    unsigned long *bitmap = (void*)block + sizeof(struct slab_alloc_block);
    // Align the bitmap
    {
    size_t mis_align = ((uintptr_t)bitmap % alignof(unsigned long));
    size_t patch = mis_align == 0 ? 0 : alignof(unsigned long)-mis_align;
    overhead += patch;
    useful_mem -= patch;
    bitmap = ((void*)bitmap) + patch;
    }
    block->bitmap = bitmap;

    if(useful_mem <= 0) {
        return -EINVAL;
    }

    size_t bits_per_obj = (alloc->obj_size * 8) + 1;
    size_t max_obj = (useful_mem*8) / bits_per_obj;

    size_t bitmap_size = (max_obj/BITS_PER_LONG +
                         ((max_obj%BITS_PER_LONG) != 0))
                         * sizeof(unsigned long);

    useful_mem -= bitmap_size;

    void *objs = ((void*)bitmap) + bitmap_size;
    // Align the object array
    {
    size_t mis_align = (uintptr_t)objs % (1ULL<<alloc->obj_align);
    size_t patch = mis_align == 0 ? 0 : (1ULL<<alloc->obj_align)-mis_align;
    overhead += patch;
    useful_mem -= patch;
    objs = ((void*)objs) + patch;
    }
    block->objects = objs;

    if(useful_mem <= 0) {
        return -EINVAL;
    }

    size_t num_slots = useful_mem / alloc->obj_size;
    if(num_slots == 0) {
        return -EINVAL;
    }

    block->num_slots = num_slots;
    block->num_free = num_slots;

    memset(block->bitmap, 0, bitmap_size);

    ilist_push_head(&alloc->block_list, &block->list_node);

    return 0;
}

struct slab_allocator *
create_static_slab_allocator(
        void *buffer,
        size_t buffer_size,
        size_t obj_size,
        order_t obj_align)
{
    struct slab_allocator *alloc = (struct slab_allocator*)buffer;
    ssize_t useful_mem = buffer_size - sizeof(struct slab_allocator);

    {
    size_t mis_align = (uintptr_t)alloc % alignof(struct slab_allocator);
    size_t patch = mis_align == 0 ? 0 : alignof(struct slab_allocator)-mis_align;
    useful_mem -= patch;
    alloc = ((void*)alloc) + patch;
    }

    if(useful_mem < 0) {
        return NULL;
    }


    init_slab_allocator(alloc, obj_size, obj_align);

    if(useful_mem > 0) {
      void *block_base = (void*)alloc + sizeof(struct slab_allocator);
      // Try to give the rest of the buffer to the slab allocator
      int res = slab_allocator_add_block(
              alloc,
              block_base,
              useful_mem,
              SLAB_ALLOC_BLOCK_STATIC);
      if(res) {
          // Sad there's not enough room left,
          // but technically we have a valid slab_allocator
          // (it'll just fail if page_alloc isn't up yet)
      }
    }

    alloc->inline_block_base = buffer;
    alloc->inline_block_size = buffer_size;

    return alloc;
}

struct slab_allocator *
create_dynamic_slab_allocator(
        size_t obj_size,
        order_t obj_align)
{
    int res;
    // Just allocate a page "buffer" and initialize it as if
    // the page was statically allocated
    paddr_t page_paddr;

    res = page_alloc(SLAB_ALLOC_BLOCK_PAGE_ORDER,
                     &page_paddr,
                     0x0);
    if(res) {
        return NULL;
    }

    void *buffer = (void*)__va(page_paddr);
    size_t buffer_size = (1ULL<<SLAB_ALLOC_BLOCK_PAGE_ORDER);

    struct slab_allocator *alloc;
    alloc = create_static_slab_allocator(
            buffer,
            buffer_size,
            obj_size,
            obj_align);

    if(alloc == NULL) {
        page_free(SLAB_ALLOC_BLOCK_PAGE_ORDER, page_paddr);
        return NULL;
    }

    return alloc;
}

void*
slab_alloc(struct slab_allocator *alloc) 
{
    ilist_node_t *node;
    ilist_for_each(node, &alloc->block_list) {
        struct slab_alloc_block *block = container_of(node, struct slab_alloc_block, list_node);
        if(block->num_free == 0) {
            continue;
        }
        dprintk("slab_alloc: Checking block %p: num_free=0x%llx, num_slots=0x%llx\n",
                block, (ull_t)block->num_free, (ull_t)block->num_slots);
        size_t first_free = bitmap_find_first_clear(block->bitmap, block->num_slots);
        if(first_free >= block->num_slots) {
            eprintk("slab_alloc Found block with num_free != 0 but bitmap has no free bits! (trying to correct)\n");
            block->num_free = 0;
            continue;
        }
        block->num_free--;
        bitmap_set(block->bitmap, first_free);

        return block->objects + (first_free * alloc->obj_size);
    }

    // TODO allocate another block using page_alloc
    return NULL;
}

void
slab_free(struct slab_allocator *alloc, void *obj) 
{
    ilist_node_t *node;
    ilist_for_each(node, &alloc->block_list) {
        struct slab_alloc_block *block = container_of(node, struct slab_alloc_block, list_node);
        if(block->num_free == block->num_slots) {
            continue;
        }
        void *objs_begin = block->objects;
        void *objs_end = block->objects + (block->num_slots * alloc->obj_size);
        if(obj < objs_begin || obj >= objs_end) {
            continue;
        }

        // Our object is in this region
        size_t index = (obj - objs_begin) / alloc->obj_size;
        bitmap_clear(block->bitmap, index);
        block->num_free++;

        // TODO
        // Check if this region is empty and dynamically allocated,
        // and free it if we can

        return;
    }
}

size_t
slab_objs_free(struct slab_allocator *alloc) {
    size_t num_free = 0;
    ilist_node_t *node;
    ilist_for_each(node, &alloc->block_list) {
        struct slab_alloc_block *block = container_of(node, struct slab_alloc_block, list_node);
        num_free += block->num_free;
    }
    return num_free;
}

size_t
slab_objs_alloc(struct slab_allocator *alloc) {
    size_t num_alloc = 0;
    ilist_node_t *node;
    ilist_for_each(node, &alloc->block_list) {
        struct slab_alloc_block *block = container_of(node, struct slab_alloc_block, list_node);
        num_alloc += (block->num_slots - block->num_free);
    }
    return num_alloc;
}

size_t
slab_objs_total(struct slab_allocator *alloc) {
    size_t num_slots = 0;
    ilist_node_t *node;
    ilist_for_each(node, &alloc->block_list) {
        struct slab_alloc_block *block = container_of(node, struct slab_alloc_block, list_node);
        num_slots += block->num_slots;
    }
    return num_slots;
}

