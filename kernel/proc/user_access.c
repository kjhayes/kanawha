
#include <kanawha/proc/aspace.h>
#include <kanawha/proc/process.h>
#include <kanawha/spinlock.h>
#include <kanawha/irq.h>
#include <kanawha/string.h>

#ifdef CONFIG_DEBUG_LOG_USER_ACCESS
#define DEBUG_PRINT(...) printk(__VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#endif

int
process_user_read(
        struct process *process,
        uintptr_t offset,
        void *dst,
        size_t length)
{
    int res;

    struct aspace *aspace = process->aspace;
    DEBUG_ASSERT(KERNEL_ADDR(aspace));

    DEBUG_PRINT("process_user_read(pid=%ld, offset=%p, dst=%p, length=0x%llx)\n",
            (sl_t)process->id, offset, dst, (ull_t)length);

    // Overflow checking
    if(~(uintptr_t)(0) - offset < length) {
        eprintk("process_user_read(process=%ld,offset=0x%llx,len=0x%llx) Overflow detected!\n",
                (sl_t)process->id,
                (ull_t)offset,
                (ull_t)length);
        return -EINVAL;
    }

    int irq_flags = spin_lock_irq_save(&aspace->lock);

    if(offset + length > aspace->vmem_region->size) {
        spin_unlock_irq_restore(&aspace->lock, irq_flags);
        return -EINVAL;
    }

    while(length > 0) {

        struct ptree_node *pnode;
        pnode = ptree_get_max_less_or_eq(&aspace->region_tree, offset);

        struct aspace_region *region =
            container_of(pnode, struct aspace_region, tree_node);

        if((pnode == NULL) ||
           (offset >= region->size + pnode->key))
        {
            spin_unlock_irq_restore(&aspace->lock, irq_flags);
            return -EINVAL;
        }

        spin_lock(&region->page_tree_lock);

        uintptr_t region_offset = offset - region->tree_node.key;

        if((region->mmap_flags & MMAP_PROT_READ) == 0) {
            // The process is not allowed to read this page
            spin_unlock(&region->page_tree_lock);
            spin_unlock_irq_restore(&aspace->lock, irq_flags);
            eprintk("process_user_read(process=%ld,offset=0x%llx,len=0x%llx)"
                    " Page is not Mapped as Readable!\n",
                (sl_t)process->id,
                (ull_t)offset,
                (ull_t)length);
            return -EINVAL;
        }

        // Get or load the page
        pnode = ptree_get_max_less_or_eq(&region->page_tree, region_offset);
        struct aspace_page *page =
            container_of(pnode, struct aspace_page, tree_node);
        if((pnode == NULL) ||
           (region_offset >= pnode->key + (1ULL<<page->order))) 
        {
            res = aspace_region_load_page(
                    region,
                    region_offset,
                    &page);
            if(res) {
                spin_unlock(&region->page_tree_lock);
                spin_unlock_irq_restore(&aspace->lock, irq_flags);
                return res;
            }
        }

        if(page == NULL) {
            spin_unlock(&region->page_tree_lock);
            spin_unlock_irq_restore(&aspace->lock, irq_flags);
            return -EINVAL;
        }

        void __phys * page_paddr = page->phys_addr;
        void *page_data = (void*)__va(page_paddr);

        uintptr_t page_offset = page->tree_node.key;
        size_t page_size = 1ULL << page->order;
        size_t page_relative_offset = region_offset - page_offset;
        size_t room_avail = page_size - page_relative_offset;
        if(length <= room_avail) {
            memcpy(dst, page_data + page_relative_offset, length);
            length = 0;
        } else {
            memcpy(dst, page_data + page_relative_offset, room_avail);
            length -= room_avail;
            dst += room_avail;
            offset += room_avail;
        }

        spin_unlock(&region->page_tree_lock);
    }
    
    spin_unlock_irq_restore(&aspace->lock, irq_flags);
    return 0;
}

int
process_user_write(
        struct process *process,
        uintptr_t offset,
        void *src,
        size_t length)
{
    int res;

    struct aspace *aspace = process->aspace;
    DEBUG_ASSERT(KERNEL_ADDR(aspace));

    // Overflow checking
    if(~(uintptr_t)(0) - offset < length) {
        return -EINVAL;
    }

    int irq_flags = spin_lock_irq_save(&aspace->lock);

    if(offset + length > aspace->vmem_region->size) {
        spin_unlock_irq_restore(&aspace->lock, irq_flags);
        return -EINVAL;
    }

    while(length > 0) {

        struct ptree_node *pnode;
        pnode = ptree_get_max_less_or_eq(&aspace->region_tree, offset);

        struct aspace_region *region =
            container_of(pnode, struct aspace_region, tree_node);

        if((pnode == NULL) ||
           (offset >= region->size + pnode->key))
        {
            spin_unlock_irq_restore(&aspace->lock, irq_flags);
            return -EINVAL;
        }

        spin_lock(&region->page_tree_lock);

        uintptr_t region_offset = offset - region->tree_node.key;

        if((region->mmap_flags & MMAP_PROT_WRITE) == 0) {
            // The process is not allowed to write this page
            spin_unlock(&region->page_tree_lock);
            spin_unlock_irq_restore(&aspace->lock, irq_flags);
            eprintk("process_user_write(process=%ld,offset=0x%llx,len=0x%llx)"
                    " Page is not Mapped as Writable!\n",
                (sl_t)process->id,
                (ull_t)offset,
                (ull_t)length);
            return -EINVAL;
        }

        // Get or load the page
        pnode = ptree_get_max_less_or_eq(&region->page_tree, region_offset);
        struct aspace_page *page =
            container_of(pnode, struct aspace_page, tree_node);
        if((pnode == NULL) ||
           (region_offset >= pnode->key + (1ULL<<page->order))) 
        {
            res = aspace_region_load_page(
                    region,
                    region_offset,
                    &page);
            if(res) {
                spin_unlock(&region->page_tree_lock);
                spin_unlock_irq_restore(&aspace->lock, irq_flags);
                return res;
            }
        }

        if(page == NULL) {
            spin_unlock(&region->page_tree_lock);
            spin_unlock_irq_restore(&aspace->lock, irq_flags);
            return -EINVAL;
        }

        if(page->flags & ASPACE_PAGE_COPY_ON_WRITE) {
            res = aspace_page_do_copy_on_write(region, page);
            if(res) {
                spin_unlock(&region->page_tree_lock);
                spin_unlock_irq_restore(&aspace->lock, irq_flags);
                return res;
            }
        }
 
        void __phys * page_paddr = page->phys_addr;
        void *page_data = (void*)__va(page_paddr);

        uintptr_t page_offset = page->tree_node.key;
        size_t page_size = 1ULL << page->order;
        size_t page_relative_offset = region_offset - page_offset;
        size_t room_avail = page_size - page_relative_offset;
        if(length <= room_avail) {
            memcpy(page_data + page_relative_offset, src, length);
            length = 0;
        } else {
            memcpy(page_data + page_relative_offset, src, room_avail);
            length -= room_avail;
            src += room_avail;
            offset += room_avail;
        }

        spin_unlock(&region->page_tree_lock);
    }

    spin_unlock_irq_restore(&aspace->lock, irq_flags);
    return 0;
}

int
process_user_strlen(
        struct process * process,
        uintptr_t offset,
        size_t max_strlen,
        size_t *out_len)
{
    int res;

    struct aspace *aspace = process->aspace;
    DEBUG_ASSERT(KERNEL_ADDR(aspace));
    DEBUG_ASSERT(ptr_orderof(aspace) >= orderof(typeof(*aspace)));
    DEBUG_ASSERT(KERNEL_ADDR(aspace->vmem_region));
    DEBUG_ASSERT(ptr_orderof(aspace->vmem_region) >= orderof(typeof(*aspace->vmem_region)));
    DEBUG_ASSERT(aspace->vmem_region->type == VMEM_REGION_TYPE_PAGED);
    DEBUG_ASSERT(aspace->vmem_region->size != 0);
    DEBUG_ASSERT(aspace->vmem_region->num_refs > 0);

    DEBUG_PRINT("process_user_strlen: PID(%ld), aspace=%p, offset=0x%lx, max=0x%lx\n",
            (sl_t)process->id, aspace, offset, max_strlen);

    int irq_flags = spin_lock_irq_save(&aspace->lock);

    size_t len = 0;

    int done = 0;
    while(!done && len < max_strlen) {

        struct ptree_node *pnode;
        pnode = ptree_get_max_less_or_eq(&aspace->region_tree, offset);

        struct aspace_region *region =
            container_of(pnode, struct aspace_region, tree_node);

        if((pnode == NULL) ||
           (offset >= region->size + pnode->key))
        {
            DEBUG_PRINT("process_user_strlen: PID(%ld) trying to access offset 0x%llx, which is outside of region [0x%llx-0x%llx)\n",
                    (sl_t)process->id,
                    (ull_t)offset,
                    (ull_t)pnode->key,
                    (ull_t)pnode->key + region->size);
            spin_unlock_irq_restore(&aspace->lock, irq_flags);
            return -EINVAL;
        }

        DEBUG_ASSERT(ptr_orderof(region->tree_node.key) >= VMEM_MIN_PAGE_ORDER);
        DEBUG_ASSERT(ptr_orderof(region->tree_node.key) <= 64);
        DEBUG_ASSERT(region->size > 0);

        DEBUG_PRINT("region=%p [%p-%p)\n", region, region->tree_node.key, region->tree_node.key + region->size);

        spin_lock(&region->page_tree_lock);

        size_t region_offset = offset - region->tree_node.key;

        if((region->mmap_flags & MMAP_PROT_READ) == 0) {
            // The process is not allowed to read this page
            spin_unlock(&region->page_tree_lock);
            spin_unlock_irq_restore(&aspace->lock, irq_flags);
            return -EINVAL;
        }

        // Get or load the page
        pnode = ptree_get_max_less_or_eq(&region->page_tree, region_offset);
        struct aspace_page *page =
            container_of(pnode, struct aspace_page, tree_node);
        if((pnode == NULL) ||
           (region_offset >= (pnode->key + (1ULL<<page->order)))) 
        {
            DEBUG_PRINT("loading page (offset=%p)\n", region_offset);
            res = aspace_region_load_page(
                    region,
                    region_offset,
                    &page);
            if(res) {
                spin_unlock(&region->page_tree_lock);
                spin_unlock_irq_restore(&aspace->lock, irq_flags);
                return res;
            }
        } else {
            DEBUG_PRINT("already had page (offset=%p)\n", region_offset);
        }

        struct ptree_node *iter = ptree_get_first(&region->page_tree);
        for(; iter != NULL; iter = ptree_get_next(iter)) {
            struct aspace_page *iter_page =
                container_of(iter, struct aspace_page, tree_node);
            DEBUG_PRINT("page=%p, phys_addr=%p, order=%ld, fs_page=%p\n",
                    iter_page,
                    iter_page->phys_addr,
                    (sl_t)iter_page->order,
                    iter_page->fs_page);
        }


        if(page == NULL) {
            spin_unlock(&region->page_tree_lock);
            spin_unlock_irq_restore(&aspace->lock, irq_flags);
            return -EINVAL;
        }

        DEBUG_ASSERT(ptr_orderof(page->phys_addr) >= VMEM_MIN_PAGE_ORDER);

        void __phys * page_paddr = page->phys_addr;
        void *page_data = (void*)__va(page_paddr);

        uintptr_t page_offset = page->tree_node.key;
        size_t page_size = 1ULL << page->order;
        size_t page_relative_offset = region_offset - page_offset;
        size_t room_avail = page_size - page_relative_offset;
        DEBUG_ASSERT(room_avail > 0);

        char *str_ptr = page_data + page_relative_offset;
        char *end_ptr = page_data + page_size;

        DEBUG_ASSERT((uintptr_t)str_ptr < (uintptr_t)end_ptr);

        while(str_ptr != end_ptr) {
            if(*str_ptr != '\0') {
                len++;
            } else {
                done = 1;
                break;
            }

            str_ptr++;
            offset++;
        }

        spin_unlock(&region->page_tree_lock);
    }
    
    spin_unlock_irq_restore(&aspace->lock, irq_flags);

    *out_len = len;
    return 0;
}

