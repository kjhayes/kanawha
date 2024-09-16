#ifndef __KANAWHA__SYSCALL_MMAP_H__
#define __KANAWHA__SYSCALL_MMAP_H__

#include <kanawha/syscall.h>
#include <kanawha/uapi/syscall.h>
#include <kanawha/file.h>
#include <kanawha/uapi/mmap.h>
#include <kanawha/list.h>

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

    struct fs_node *fs_node;

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

    ilist_t process_list;
};

// Create a new mmap for the process
int
mmap_create(size_t size, struct process *process);

// Attach a process to the mmap,
int
mmap_attach(struct mmap *map, struct process *process);

// Deattach a process from the mmap,
// if this is the last process attached, then the mmap will be
// freed.
int
mmap_deattach(struct mmap *map, struct process *process);

int
mmap_map_region(
        struct process *process,
        fd_t file,
        uintptr_t file_offset,
        uintptr_t *hint_offset,
        size_t size,
        unsigned long prot_flags,
        unsigned long mmap_flags);

int
mmap_map_region_exact(
        struct process *process,
        fd_t file,
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

int
mmap_user_strlen(
        struct process *process,
        uintptr_t offset,
        size_t max_strlen,
        size_t *strlen);

#endif
