#ifndef __KANAWHA__SYSCALL_MMAP_H__
#define __KANAWHA__SYSCALL_MMAP_H__

#include <kanawha/syscall.h>
#include <kanawha/file.h>

struct process;

#define MMAP_PROT_READ  (1ULL<<0)
#define MMAP_PROT_WRITE (1ULL<<1)
#define MMAP_PROT_EXEC  (1ULL<<2)

// Mutually Exclusive Types
#define MMAP_SHARED  (0b00 << 0)
#define MMAP_PRIVATE (0b01 << 0)
#define MMAP_ANON    (0b10 << 0)
#define MMAP_ANONYMOUS MMAP_ANON

// "where" is not a suggestion
#define MMAP_FIXED (1ULL << 2)

// If we map on top of another mapping,
// that mapping can be removed, must
// be used with "MAP_FIXED"
#define MMAP_REPLACE (1ULL << 3)

int
syscall_mmap(
        struct process *process,
        fd_t file,
        size_t file_offset,
        void __user **where,
        size_t size,
        unsigned long prot_flags,
        unsigned long mmap_flags);

struct process;
struct mmap_region;

// This page is mapped in
#define MMAP_PAGE_MAPPED  (1ULL<<0)
// This page is not backed by the region file_descriptor,
// reclaiming it would require terminating the process (OOM)
#define MMAP_PAGE_ANON (1ULL<<1)
// Make an anonymous copy of this page when we write it
#define MMAP_PAGE_COPY_ON_WRITE (1ULL<<2)
struct mmap_page
{
    paddr_t phys_addr;
    order_t order;

    unsigned long flags;
    struct fs_page *fs_page;

    struct ptree_node tree_node;
};

struct mmap_region
{
    struct mmap *mmap;

    struct file_descriptor *desc;
    uintptr_t file_offset;
    uintptr_t size;

    unsigned long prot_flags;
    unsigned long mmap_flags;

    spinlock_t page_tree_lock;
    struct ptree page_tree;

    struct ptree_node tree_node;
};

struct mmap
{
    spinlock_t lock;

    struct ptree region_tree;

    struct vmem_region *vmem_region;
};

int
mmap_init(struct process *process, size_t size);

int
mmap_deinit(struct process *process);

int
mmap_map_region(
        struct process *process,
        struct file_descriptor *desc,
        uintptr_t file_offset,
        uintptr_t mmap_offset,
        size_t size,
        unsigned long prot_flags,
        unsigned long mmap_flags);

int
mmap_unmap_region(
        struct process *process,
        uintptr_t mmap_offset);

int
mmap_read(
        struct process *process,
        uintptr_t offset,
        void *dst,
        size_t length);

int
mmap_write(
        struct process *process,
        uintptr_t offset,
        void *dst,
        size_t length);

#endif