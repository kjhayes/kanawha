#ifndef __KANAWHA__ASPACE_H__
#define __KANAWHA__ASPACE_H__

#include <kanawha/uapi/file.h>
#include <kanawha/uapi/mmap.h>
#include <kanawha/list.h>
#include <kanawha/pointer.h>
#include <kanawha/ptree.h>
#include <kanawha/spinlock.h>
#include <kanawha/vmem.h>

struct process;
struct aspace_region;

// This page is mapped in
#define ASPACE_PAGE_MAPPED  (1ULL<<0)
// This page is not backed by the region file_descriptor,
// reclaiming it would require terminating the process (OOM)
#define ASPACE_PAGE_ANON (1ULL<<1)
// Make an anonymous copy of this page when we write it
#define ASPACE_PAGE_COPY_ON_WRITE (1ULL<<2)
struct aspace_page
{
    void __phys * phys_addr;
    order_t order;

    unsigned long flags;
    struct fs_page *fs_page;

    struct ptree_node tree_node;
};

struct aspace_region
{
    struct aspace *aspace;

    struct fs_node *fs_node;

    uintptr_t file_offset;
    uintptr_t size;

    unsigned long prot_flags;
    unsigned long mmap_flags;

    spinlock_t page_tree_lock;
    struct ptree page_tree;

    struct ptree_node tree_node;
};

struct aspace 
{
    spinlock_t lock;

    struct ptree region_tree;
    struct vmem_region *vmem_region;

    ilist_t process_list;
};

// Create a new aspace for the process
int
aspace_create(size_t size, struct process *process);

// Attach a process to the aspace,
int
aspace_attach(struct aspace *map, struct process *process);

// Deattach a process from the aspace,
// if this is the last process attached, then the aspace will be
// freed.
int
aspace_deattach(struct aspace *map, struct process *process);

int
aspace_map_region(
        struct process *process,
        fd_t file,
        uintptr_t file_offset,
        uintptr_t *hint_offset,
        size_t size,
        unsigned long prot_flags,
        unsigned long mmap_flags);

int
aspace_map_region_exact(
        struct process *process,
        fd_t file,
        uintptr_t file_offset,
        uintptr_t aspace_offset,
        size_t size,
        unsigned long prot_flags,
        unsigned long mmap_flags);

int
aspace_unmap_region(
        struct process *process,
        uintptr_t aspace_offset);

int
aspace_read(
        struct process *process,
        uintptr_t offset,
        void *dst,
        size_t length);

int
aspace_write(
        struct process *process,
        uintptr_t offset,
        void *dst,
        size_t length);

int
aspace_user_strlen(
        struct process *process,
        uintptr_t offset,
        size_t max_strlen,
        size_t *strlen);

int
aspace_region_load_page(
        struct aspace_region *region,
        uintptr_t page_offset,
        struct aspace_page **out);

int
aspace_region_map_page(
        struct aspace_region *region,
        struct aspace_page *page);

int
aspace_page_do_copy_on_write(
        struct aspace_region *region,
        struct aspace_page *page);

int
aspace_page_fault_handler(
        struct vmem_region_ref *ref,
        uintptr_t offset,
        unsigned long flags,
        void *priv_state);

#endif
