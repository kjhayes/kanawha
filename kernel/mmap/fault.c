
#include <kanawha/mmap.h>
#include <kanawha/spinlock.h>
#include <kanawha/irq.h>

// Page Fault Handlers

int
mmap_not_present_page_fault_handler(
        struct mmap *mmap,
        struct mmap_region *region,
        uintptr_t region_offset)
{
    int res;

    dprintk("mmap_not_present_page_fault_handler: region->base=%p, region_offset=%p, region->file_offset=%p\n",
            region->tree_node.key, region_offset, region->file_offset);

    if(region_offset >= region->size) {
        goto unhandled;
    }
    
    struct ptree_node *pnode = ptree_get_max_less_or_eq(
            &region->page_tree, region_offset);

    struct mmap_page *page =
        container_of(pnode, struct mmap_page, tree_node);

    if(pnode == NULL ||
       ((pnode->key + (1ULL<<page->order)) <= region_offset)) {
        res = mmap_region_load_page(
                region,
                region_offset,
                &page);
        if(res) {
            goto unhandled;
        }
    }
    dprintk("mmap_not_present_page_fault_handler: page=%p\n",
            page);

    if(page == NULL) {
        goto unhandled;
    }

    res = mmap_region_map_page(
            region,
            page);
    if(res) {
        goto unhandled;
    }

    dprintk("mmap_not_present_page_fault_handler: mapped page!\n");
    return PAGE_FAULT_HANDLED;

unhandled:
    return PAGE_FAULT_UNHANDLED;
}


int
mmap_page_fault_handler(
        struct vmem_region_ref *ref,
        uintptr_t offset,
        unsigned long pf_flags,
        void *priv_state)
{
    dprintk("mmap_page_fault_handler offset=%p, pf_flags=0x%llx\n",
            offset, (ull_t)pf_flags);
    struct mmap *mmap = priv_state;

    if((pf_flags & PF_FLAG_USERMODE) == 0) {
        eprintk("Kernel attempted to access process mmap region directly! (mmap_offset=%p)\n",
                offset);
        return PAGE_FAULT_UNHANDLED;
    }

    int res;
    int irq_flags = spin_lock_irq_save(&mmap->lock);

    struct ptree_node *pnode;
    pnode = ptree_get_max_less_or_eq(&mmap->region_tree, offset);
    if(pnode == NULL) {
        spin_unlock_irq_restore(&mmap->lock, irq_flags);
        return PAGE_FAULT_UNHANDLED;
    }

    struct mmap_region *region =
        container_of(pnode, struct mmap_region, tree_node);

    spin_lock(&region->page_tree_lock);

    uintptr_t region_offset = offset - region->tree_node.key;

    if(pf_flags & PF_FLAG_NOT_PRESENT) {
        res = mmap_not_present_page_fault_handler(
                mmap,
                region,
                region_offset);

        spin_unlock(&region->page_tree_lock);
        spin_unlock_irq_restore(&mmap->lock, irq_flags);
        return res;
    }

    pnode = ptree_get_max_less_or_eq(
            &region->page_tree,
            region_offset);
    DEBUG_ASSERT(KERNEL_ADDR(pnode));

    struct mmap_page *page =
        container_of(pnode, struct mmap_page, tree_node);

    if((page->flags & MMAP_PAGE_COPY_ON_WRITE)&&(pf_flags & PF_FLAG_WRITE))
    {
        res = mmap_page_do_copy_on_write(region, page); 
        if(res) {
            spin_unlock(&region->page_tree_lock);
            spin_unlock_irq_restore(&mmap->lock, irq_flags);
            return PAGE_FAULT_UNHANDLED;
        }

        spin_unlock(&region->page_tree_lock);
        spin_unlock_irq_restore(&mmap->lock, irq_flags);
        return PAGE_FAULT_HANDLED;
    }

    spin_unlock(&region->page_tree_lock);
    spin_unlock_irq_restore(&mmap->lock, irq_flags);
    return PAGE_FAULT_UNHANDLED;
}
