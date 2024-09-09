#ifndef __KANAWHA__VMEM_H__
#define __KANAWHA__VMEM_H__

#ifdef CONFIG_X64 
#include <arch/x64/vmem.h>
#else
#error "Architecture did not provide vmem.h!"
#endif

#ifndef VMEM_MIN_PAGE_ORDER
#error "Architecture did not define VMEM_MIN_PAGE_ORDER!"
#endif

#include <kanawha/stdint.h>
#include <kanawha/ptree.h>
#include <kanawha/refcount.h>
#include <kanawha/printk.h>
#include <kanawha/list.h>
#include <kanawha/stdint.h>

#define __phys \
    __attribute__((address_space(4)))

static inline vaddr_t
__va(paddr_t paddr) {
    return paddr + CONFIG_VIRTUAL_BASE;
}

static inline paddr_t
__pa(vaddr_t vaddr) {
    return vaddr - CONFIG_VIRTUAL_BASE;
}

// The architecture can define a more strict or lax version
// of this check if needed
//
// At minimum, this needs to always return 0 if ptr==NULL
#ifndef KERNEL_ADDR 
#define KERNEL_ADDR(ptr) \
    (((uintptr_t)ptr & (1ULL<<((sizeof(void*)*8)-1))) != 0)
#endif

_Static_assert((!KERNEL_ADDR(0)), "Architecture defined KERNEL_ADDR must return 0 for NULL!");
_Static_assert((KERNEL_ADDR(CONFIG_VIRTUAL_BASE)), "Architecture defined KERNEL_ADDR does not return 1 for CONFIG_VIRTUAL_BASE!");

#define VMEM_REGION_WRITE (1UL<<0)
#define VMEM_REGION_READ  (1UL<<1)
#define VMEM_REGION_EXEC  (1UL<<2)
#define VMEM_REGION_USER  (1UL<<3)
#define VMEM_REGION_NOCACHE (1UL<<4)

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
    vaddr_t virt_addr;
};

typedef enum
vmem_region_type {
    VMEM_REGION_TYPE_DIRECT,
    VMEM_REGION_TYPE_PAGED,
} vmem_region_type_t;

#define PAGE_FAULT_HANDLED   0
#define PAGE_FAULT_UNHANDLED 1

#define PF_FLAG_NOT_PRESENT (1ULL<<0)
#define PF_FLAG_READ        (1ULL<<1)
#define PF_FLAG_WRITE       (1ULL<<2)
#define PF_FLAG_EXEC        (1ULL<<3)
#define PF_FLAG_USERMODE    (1ULL<<4)
typedef int(page_fault_f)(struct vmem_region_ref *region, uintptr_t offset, unsigned long flags, void *priv_state);

struct vmem_region 
{
    spinlock_t lock;
    size_t num_refs;
    ilist_t ref_list;

    vmem_region_type_t type;
    union {
        struct {
            paddr_t phys_base;
            unsigned long flags;
        } direct;
        struct {
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
vmem_region_create_direct(
        paddr_t paddr,
        size_t size,
        unsigned long flags);

struct vmem_region *
vmem_region_create_paged(
        size_t size,
        page_fault_f *fault_handler,
        void *priv_state);

int
vmem_region_destroy(struct vmem_region *region);

struct vmem_region_ref *
vmem_map_get_region(struct vmem_map *map, vaddr_t addr);

int
vmem_map_map_region(
        struct vmem_map *map,
        struct vmem_region *region,
        vaddr_t base);

int
vmem_map_unmap_region(
        struct vmem_map *map,
        struct vmem_region_ref *ref);

// Activate a specific vmem_map on the current CPU
int vmem_map_activate(struct vmem_map *map);
// Deactivate the current CPU's vmem_map, and map in the
// default kernel mapping
int vmem_map_deactivate(void);

// Get's the currently active vmem_map for the current CPU
// (Assumes preemption is already disabled or we are pinned to the current CPU)
struct vmem_map *
vmem_map_get_current(void);

int
vmem_flush_map(struct vmem_map *map);

int
vmem_flush_region(struct vmem_region *region);

int
vmem_paged_region_map(
        struct vmem_region *region,
        size_t offset,
        paddr_t phys_addr,
        size_t size,
        unsigned long flags);

int
vmem_paged_region_unmap(
        struct vmem_region *region,
        size_t offset,
        size_t size);

struct vmem_map *
vmem_get_default_map(void);

// Forces "region" to appear at "virtual_address" in the default map,
// and in all thread vmem mappings
int
vmem_force_mapping(struct vmem_region *region, vaddr_t virtual_address);
int
vmem_relax_mapping(vaddr_t virtual_address);

int vmem_map_handle_page_fault(
        vaddr_t faulting_address,
        unsigned long flags,
        struct vmem_map *map);

int vmem_percpu_init(void);

// Architecture API

int arch_vmem_map_init(struct vmem_map *map);
int arch_vmem_map_deinit(struct vmem_map *map);
int arch_vmem_region_init(struct vmem_region *region);
int arch_vmem_region_deinit(struct vmem_region *region);

int arch_vmem_map_map_region(struct vmem_map *map, struct vmem_region_ref *ref);
int arch_vmem_map_unmap_region(struct vmem_map *map, struct vmem_region_ref *ref);

int arch_vmem_map_activate(struct vmem_map *map);
int arch_vmem_map_flush(struct vmem_map *map);

int arch_vmem_paged_region_map(
        struct vmem_region *region,
        size_t offset,
        paddr_t phys_addr,
        size_t size,
        unsigned long flags);
int arch_vmem_paged_region_unmap(
        struct vmem_region *region,
        size_t offset,
        size_t size);

void
arch_dump_vmem_map(printk_f *printer, struct vmem_map *map);

#endif
