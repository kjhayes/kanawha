#ifndef __KANAWHA__VMEM_H__
#define __KANAWHA__VMEM_H__

#include <kanawha/excp.h>

#if defined(CONFIG_X64)
#include <arch/x64/vmem.h>
#elif defined(CONFIG_RISCV64)
#include <arch/riscv64/vmem.h>
#elif defined(CONFIG_ARM64)
#include <arch/arm64/vmem.h>
#else
#error "Architecture did not provide vmem.h!"
#endif

#ifndef VMEM_MIN_PAGE_ORDER
#error "Architecture did not define VMEM_MIN_PAGE_ORDER!"
#endif

#include <kanawha/list.h>
#include <kanawha/pointer.h>
#include <kanawha/printk.h>
#include <kanawha/ptree.h>
#include <kanawha/spinlock.h>
#include <kanawha/types.h>

_Static_assert((!KERNEL_ADDR(NULL)),
               "Architecture defined KERNEL_ADDR must return 0 for NULL!");

#define VMEM_REGION_WRITE (1UL << 0)
#define VMEM_REGION_READ (1UL << 1)
#define VMEM_REGION_EXEC (1UL << 2)
#define VMEM_REGION_USER (1UL << 3)
#define VMEM_REGION_NOCACHE (1UL << 4)

struct vmem_map
{
    struct arch_vmem_map arch_state;

    spinlock_t lock;

    size_t active_on;

    struct ptree mapping_root;
};

// Represents the link between an entire address space
// and a specific subregion within that address space
// that might be present in multiple address spaces
struct vmem_region_ref
{

    struct vmem_map *map;
    struct vmem_region *region;

    struct ptree_node map_node;
    ilist_node_t region_node;

    unsigned long flags;
    void *virt_addr;
};

typedef enum vmem_region_type
{
    VMEM_REGION_TYPE_DIRECT,
    VMEM_REGION_TYPE_PAGED,
} vmem_region_type_t;

#define PAGE_FAULT_HANDLED 0
#define PAGE_FAULT_UNHANDLED 1

#define PF_FLAG_NOT_PRESENT (1ULL << 0)
#define PF_FLAG_READ (1ULL << 1)
#define PF_FLAG_WRITE (1ULL << 2)
#define PF_FLAG_EXEC (1ULL << 3)
#define PF_FLAG_USERMODE (1ULL << 4)
typedef int(page_fault_f)(struct excp_state *state,
                          struct vmem_region_ref *region,
                          uintptr_t offset,
                          unsigned long flags,
                          void *priv_state);

struct vmem_region
{
    spinlock_t lock;
    size_t num_refs;
    ilist_t ref_list;

    vmem_region_type_t type;
    union
    {
        struct
        {
            void __phys *phys_base;
            unsigned long flags;
        } direct;
        struct
        {
            page_fault_f *fault_handler;
            void *priv_state;
        } paged;
    };
    size_t size;

    struct arch_vmem_region arch_state;
};

struct vmem_map *
vmem_map_create(void);
int
vmem_map_destroy(struct vmem_map *map);

struct vmem_region *
vmem_region_create_direct(void __phys *paddr, size_t size, unsigned long flags);

struct vmem_region *
vmem_region_create_paged(size_t size,
                         page_fault_f *fault_handler,
                         void *priv_state);

int
vmem_region_destroy(struct vmem_region *region);

// Return the minimum virtual alignment the region
// can be mapped to
order_t
vmem_region_alignment(struct vmem_region *region);

struct vmem_region_ref *
vmem_map_get_region(struct vmem_map *map, void *addr);

int
vmem_map_map_region(struct vmem_map *map,
                    struct vmem_region *region,
                    void *base);

int
vmem_map_unmap_region(struct vmem_map *map, struct vmem_region_ref *ref);

// Activate a specific vmem_map on the current CPU
int
vmem_map_activate(struct vmem_map *map);
// Deactivate the current CPU's vmem_map, and map in the
// default kernel mapping
int
vmem_map_deactivate(void);

// Get's the currently active vmem_map for the current CPU
// (Assumes preemption is already disabled or we are pinned to the current CPU)
struct vmem_map *
vmem_map_get_current(void);

int
vmem_flush_map(struct vmem_map *map);

int
vmem_flush_region(struct vmem_region *region);

int
vmem_paged_region_map(struct vmem_region *region,
                      size_t offset,
                      void __phys *phys_addr,
                      size_t size,
                      unsigned long flags);

int
vmem_paged_region_unmap(struct vmem_region *region, size_t offset, size_t size);

struct vmem_map *
vmem_get_default_map(void);

// Forces "region" to appear at "virtual_address" in the default map,
// and in all thread vmem mappings
int
vmem_force_mapping(struct vmem_region *region, void *virtual_address);
int
vmem_relax_mapping(void *virtual_address);

int
vmem_map_handle_page_fault(struct excp_state *state,
                           void *faulting_address,
                           unsigned long flags,
                           struct vmem_map *map);
int
vmem_percpu_init(void);

// Architecture API

int
arch_vmem_map_init(struct vmem_map *map);
int
arch_vmem_map_deinit(struct vmem_map *map);
int
arch_vmem_region_init(struct vmem_region *region);
int
arch_vmem_region_deinit(struct vmem_region *region);

order_t
arch_vmem_region_alignment(struct vmem_region *region);

int
arch_vmem_map_map_region(struct vmem_map *map, struct vmem_region_ref *ref);
int
arch_vmem_map_unmap_region(struct vmem_map *map, struct vmem_region_ref *ref);

int
arch_vmem_map_activate(struct vmem_map *map);
int
arch_vmem_map_flush(struct vmem_map *map);

int
arch_vmem_paged_region_map(struct vmem_region *region,
                           size_t offset,
                           void __phys *phys_addr,
                           size_t size,
                           unsigned long flags);
int
arch_vmem_paged_region_unmap(struct vmem_region *region,
                             size_t offset,
                             size_t size);

#define VMEM_ACCESS_PRESENT (1UL << 0)
#define VMEM_ACCESS_READABLE (1UL << 1)
#define VMEM_ACCESS_WRITEABLE (1UL << 2)
#define VMEM_ACCESS_EXECUTABLE (1UL << 3)
#define VMEM_ACCESS_USER (1UL << 4)
#define VMEM_ACCESS_KERNEL (1UL << 5)
#define VMEM_ACCESS_NOCACHE (1UL << 6)
int
arch_vmem_map_walk(
        struct vmem_map *map,
        void *vaddr,
        void __phys **phys_out,
        unsigned long *vmem_access_flags);

void
arch_dump_vmem_map(printk_f *printer, struct vmem_map *map);

#define VMEM_VERIFY_ACCESS_KERNEL (1ULL << 0)
#define VMEM_VERIFY_ACCESS_READ (1ULL << 1)
#define VMEM_VERIFY_ACCESS_WRITE (1ULL << 2)
#define VMEM_VERIFY_ACCESS_EXEC (1ULL << 3)
int
vmem_verify_access(void *loc, size_t size, unsigned long flags);

int
vmem_map_address_is_mapped(
        struct vmem_map *map,
        void *vaddr);
int
vmem_map_translate(
        struct vmem_map *map,
        void *vaddr,
        void __phys **phys_out);

#endif
