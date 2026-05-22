
#include <kanawha/assert.h>
#include <kanawha/excp.h>
#include <kanawha/init.h>
#include <kanawha/irq_domain.h>
#include <kanawha/mem_flags.h>
#include <kanawha/page_alloc.h>
#include <kanawha/paging/paging.h>
#include <kanawha/paging/pagetable.h>
#include <kanawha/printk.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/thread.h>
#include <kanawha/types.h>
#include <kanawha/vmem.h>
#include <kanawha/xcall.h>

#define PAGING_PT_ENTRY_BUFLEN (8)


static inline struct vmem_map_paging_state *
vmem_map_get_paging_state(struct vmem_map *map)
{
    return arch_get_vmem_map_paging_state(map);
}
static inline struct vmem_region_paging_state *
vmem_region_get_paging_state(struct vmem_region *region)
{
    return arch_get_vmem_region_paging_state(region);
}

static inline unsigned long
paging_entry_flags_from_vmem_region_flags(
        unsigned long vmem_flags)
{
    unsigned long entry_flags = 0;
    entry_flags |= PAGING_ENTRY_PRESENT;
    if(vmem_flags & VMEM_REGION_READ) {
        entry_flags |= PAGING_ENTRY_READABLE;
    }
    if(vmem_flags & VMEM_REGION_WRITE) {
        entry_flags |= PAGING_ENTRY_WRITEABLE;
    }
    if(vmem_flags & VMEM_REGION_EXEC) {
        entry_flags |= PAGING_ENTRY_EXECUTABLE;
    }
    if(vmem_flags & VMEM_REGION_NOCACHE) {
        entry_flags |= PAGING_ENTRY_CACHE_DISABLE;
    }
    if(vmem_flags & VMEM_REGION_USER) {
        entry_flags |= PAGING_ENTRY_USER_ACCESS;
    }
    entry_flags |= PAGING_ENTRY_KERNEL_ACCESS;
    return entry_flags;
}

static inline unsigned long
paging_vmem_access_flags_from_entry_flags(
        unsigned long entry_flags)
{
    if(!(entry_flags & PAGING_ENTRY_IS_LEAF)) {
        return 0;
    }

    unsigned long vmem_flags = 0;
    if(entry_flags & PAGING_ENTRY_PRESENT) {
        vmem_flags |= VMEM_ACCESS_PRESENT;
    }
    if(entry_flags & PAGING_ENTRY_READABLE) {
        vmem_flags |= VMEM_ACCESS_READABLE;
    }
    if(entry_flags & PAGING_ENTRY_WRITEABLE) {
        vmem_flags |= VMEM_ACCESS_WRITEABLE;
    }
    if(entry_flags & PAGING_ENTRY_EXECUTABLE) {
        vmem_flags |= VMEM_ACCESS_EXECUTABLE;
    }
    if(entry_flags & PAGING_ENTRY_CACHE_DISABLE) {
        vmem_flags |= VMEM_ACCESS_NOCACHE;
    }
    if(entry_flags & PAGING_ENTRY_USER_ACCESS) {
        vmem_flags |= VMEM_ACCESS_USER;
    }
    if(entry_flags & PAGING_ENTRY_KERNEL_ACCESS) {
        vmem_flags |= VMEM_ACCESS_KERNEL;
    }

    return vmem_flags;
}

static int
arch_vmem_region_init_direct(struct vmem_region *region)
{
    int res;

    const struct paging_mode *mode = current_paging_mode();
    DEBUG_ASSERT(KERNEL_ADDR(mode));

    struct vmem_region_paging_state *state =
        vmem_region_get_paging_state(region);

    int root_level = paging_mode_num_levels(mode)-1;
    unsigned long flags = 0;

    res = pagetable_init(
            &state->pagetable,
            root_level,
            root_level,
            0,
            flags);
    if(res) {
        return res;
    }

    res = pagetable_drill(
            &state->pagetable,
            (void*)0,
            region->direct.phys_base,
            region->size,
            paging_entry_flags_from_vmem_region_flags(region->direct.flags));
    if(res) {
        pagetable_deinit(&state->pagetable);
        return res;
    }

    return 0;
}

static int
arch_vmem_region_init_paged(struct vmem_region *region)
{
    int res;

    const struct paging_mode *mode = current_paging_mode();
    DEBUG_ASSERT(KERNEL_ADDR(mode));

    struct vmem_region_paging_state *state =
        vmem_region_get_paging_state(region);

    int root_level = paging_mode_num_levels(mode)-1;
    unsigned long flags = 0;

    int max_leaf_level = 0;
    if(root_level > 2) {
        max_leaf_level = 1;
    }
    if(root_level > 3) {
        max_leaf_level = 2;
    }

    res = pagetable_init(
            &state->pagetable,
            root_level,
            max_leaf_level,
            max_leaf_level + 1,
            flags);
    if(res) {
        return res;
    }

    return 0;
}

int
arch_vmem_region_init(struct vmem_region *region)
{
    switch(region->type)
    {
    case VMEM_REGION_TYPE_DIRECT:
        return arch_vmem_region_init_direct(region);
    case VMEM_REGION_TYPE_PAGED:
        return arch_vmem_region_init_paged(region);
    default:
        return -EINVAL;
    }
}

order_t
arch_vmem_region_alignment(struct vmem_region *region)
{
    order_t order;
    const struct paging_mode *mode = arch_paging_mode();

    struct vmem_region_paging_state *state = vmem_region_get_paging_state(region);

    if(region->type == VMEM_REGION_TYPE_DIRECT)
    {
        order = paging_level_entry_region_order(mode, state->pagetable.max_leaf_level);
    }
    else
    {
        order = paging_level_entry_region_order(mode, state->pagetable.min_map_level);
    }
    return order;
}

// This region should not exist in any maps at this point
int
arch_vmem_region_deinit(struct vmem_region *region)
{
    int res;

    struct vmem_region_paging_state *state =
        vmem_region_get_paging_state(region);

    res = pagetable_deinit(&state->pagetable);
    if(res) {
        return res;
    }

    return 0;
}

int
arch_vmem_map_map_region(struct vmem_map *map, struct vmem_region_ref *ref)
{
    int res;

    struct vmem_region *region = ref->region;
    struct vmem_region_paging_state *region_state = vmem_region_get_paging_state(region);
    struct vmem_map_paging_state *map_state = vmem_map_get_paging_state(map);

    void *vaddr = ref->virt_addr;
    size_t size = region->size;

    res = pagetable_map(
            &map_state->pagetable,
            &region_state->pagetable,
            vaddr,
            size);
    if(res) {
        return res;
    }

    return 0;
}

int
arch_vmem_map_unmap_region(struct vmem_map *map, struct vmem_region_ref *ref)
{
    int res;

    struct vmem_region *region = ref->region;
    struct vmem_region_paging_state *region_state = vmem_region_get_paging_state(region);
    struct vmem_map_paging_state *map_state = vmem_map_get_paging_state(map);

    void *vaddr = ref->virt_addr;
    size_t size = region->size;

    res = pagetable_unmap(
            &map_state->pagetable,
            vaddr,
            size);
    if(res) {
        return res;
    }

    return 0;
}

int
arch_vmem_paged_region_map(struct vmem_region *region,
                           size_t offset,
                           void __phys *phys_addr,
                           size_t size,
                           unsigned long flags)
{
    int res;

    struct vmem_region_paging_state *region_state;
    region_state = vmem_region_get_paging_state(region);

    res = pagetable_drill(
            &region_state->pagetable,
            (void*)offset,
            phys_addr,
            size,
            paging_entry_flags_from_vmem_region_flags(flags));
    if(res) {
        return res;
    }

    return 0;
}

int
arch_vmem_paged_region_unmap(struct vmem_region *region,
                             size_t offset,
                             size_t size)
{
    int res;

    struct vmem_region_paging_state *region_state;
    region_state = vmem_region_get_paging_state(region);

    res = pagetable_undrill(
            &region_state->pagetable,
            (void*)offset,
            size);
    if(res) {
        return res;
    }

    return 0;
}
int
arch_vmem_map_activate(struct vmem_map *map)
{
    int res;

    struct vmem_map_paging_state *state;
    state = vmem_map_get_paging_state(map);

    void __phys *root = pagetable_root(&state->pagetable);
    int root_level = pagetable_root_level(&state->pagetable);

    res = arch_paging_set_pt_root(root, root_level);
    if(res) {
        return res;
    }

    res = arch_paging_flush_tlb(root, 1);
    DEBUG_ASSERT_MSG(res == 0, "Failed to flush TLB on vmem_map_activate!");

    return 0;
}

static void
tlb_shootdown_xcall(void *with_pt_root_phys)
{
    // Disable IRQs to make absolutely sure we can't change the
    // value of cr3 by accident
    int irq_flags = disable_save_irqs();

    void __phys *pt_root = (void __phys *)with_pt_root_phys;
    arch_paging_flush_tlb(pt_root, 0);

    enable_restore_irqs(irq_flags);
}

int
arch_vmem_map_flush(struct vmem_map *map)
{
    int res;

    if(map->active_on <= 0) {
        return 0;
    }

    if(map->active_on == 1 && map == vmem_map_get_current()) {
        arch_paging_flush_tlb(NULL, 1);
        return 0;
    }

    struct vmem_map_paging_state *state;
    state = vmem_map_get_paging_state(map);

    void __phys *root = pagetable_root(&state->pagetable);

    res = xcall_broadcast(tlb_shootdown_xcall, (void *)root);
    if(res)
    {
        return res;
    }

    return 0;
}

void
arch_dump_vmem_map(printk_f *printer, struct vmem_map *map)
{
    struct vmem_map_paging_state *state = vmem_map_get_paging_state(map);
    pagetable_dump(printer, &state->pagetable);
    return;
}

// init/deinit
int
arch_vmem_map_init(struct vmem_map *map)
{
    int res;

    const struct paging_mode *mode = current_paging_mode();
    int root_level = paging_mode_num_levels(mode) - 1;

    struct vmem_map_paging_state *state = vmem_map_get_paging_state(map);

    unsigned long flags = 0;

    res = pagetable_init(
            &state->pagetable,
            root_level,
            root_level,
            0,
            flags);
    if(res) {
        return res;
    }

    return 0;
}

// Every region should have been unmapped from this map already
int
arch_vmem_map_deinit(struct vmem_map *map)
{
    int res;
    struct vmem_map_paging_state *state = vmem_map_get_paging_state(map);
    res = pagetable_deinit(&state->pagetable);
    if(res) {
        return res;
    }
    return 0;
}

int
arch_vmem_map_walk(
        struct vmem_map *map,
        void *vaddr,
        void __phys **phys_out,
        unsigned long *flags_out)
{ 
    int res;

    struct vmem_map_paging_state *state = vmem_map_get_paging_state(map);

    void __phys *page;
    order_t page_order;
    unsigned long entry_flags;
    res = pagetable_walk_leaf(
            &state->pagetable,
            vaddr,
            &page,
            &page_order,
            &entry_flags);
    if(res) {
        return res;
    }

    size_t offset = ((uintptr_t)vaddr) & ((1UL<<page_order)-1);

    void __phys *phys = page + offset;
    unsigned long flags = paging_vmem_access_flags_from_entry_flags(entry_flags);
    if(phys_out) {
        *phys_out = phys;
    }
    if(flags_out) {
        *flags_out = flags;
    }
    dprintk("arch_vmem_map_walk: got virt=%p, phys=%p, flags=0x%lx\n",
            vaddr,
            phys,
            flags);
    return 0;
}

