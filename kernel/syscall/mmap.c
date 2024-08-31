
#include <kanawha/syscall.h>
#include <kanawha/process.h>
#include <kanawha/file.h>
#include <kanawha/stdint.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/ptree.h>
#include <kanawha/vmem.h>
#include <kanawha/stddef.h>
#include <kanawha/assert.h>
#include <kanawha/process.h>
#include <kanawha/page_alloc.h>
#include <kanawha/syscall/mmap.h>

int
syscall_mmap(
        struct process *process,
        fd_t file,
        size_t file_offset,
        void __user *where,
        size_t size,
        unsigned long prot_flags,
        unsigned long mmap_flags)
{
    int res;

    // Mis-aligned/Mis-sized
    if(file != NULL_FD && (ptr_orderof(file_offset) < VMEM_MIN_PAGE_ORDER)) {
        wprintk("syscall_mmap: file_offset is not aligned to the minimum vmem page size!\n");
        return -EINVAL;
    }
    if(ptr_orderof(where) < VMEM_MIN_PAGE_ORDER) {
        wprintk("syscall_mmap: virtual address is not aligned to the minimum vmem page size!\n");
        return -EINVAL;
    }
    if(ptr_orderof(size) < VMEM_MIN_PAGE_ORDER) {
        wprintk("syscall_mmap: size is not aligned to the minimum vmem page size!\n");
        return -EINVAL;
    }

    res = mmap_map_region(
            process,
            file,
            file_offset,
            (uintptr_t)where,
            size,
            prot_flags,
            mmap_flags);
    if(res) {
        return res;
    }

    return 0;
}

int
syscall_munmap(
        struct process *process,
        void __user *mapping) 
{
    int res;
    struct mmap *mmap = &process->mmap;
    struct ptree_node *node;

    spin_lock(&mmap->lock);

    node = ptree_get_max_less_or_eq(
            &mmap->region_tree,
            (uintptr_t)mapping);
    if(node == NULL) {
        spin_unlock(&mmap->lock);
        return -ENXIO;
    }

    struct mmap_region *region =
        container_of(node, struct mmap_region, tree_node);

    res = mmap_unmap_region(
            process,
            region->tree_node.key);
    if(res) {
        spin_unlock(&mmap->lock);
        return res;
    }
    
    spin_unlock(&mmap->lock);

    return 0;
}

static int
mmap_page_fault_handler(
        struct vmem_region_ref *ref,
        uintptr_t offset,
        unsigned long flags,
        void *priv_state);

int
mmap_init(
        struct process *process,
        size_t size)
{
    struct mmap *mmap = &process->mmap;

    memset(mmap, 0, sizeof(struct mmap));

    spinlock_init(&mmap->lock);
    ptree_init(&mmap->region_tree);

    mmap->vmem_region =
        vmem_region_create_paged(
                size,
                mmap_page_fault_handler,
                mmap);

    if(mmap->vmem_region == NULL) {
        return -ENOMEM;
    }

    return 0;
}

int
mmap_deinit(
        struct process *process)
{
    struct mmap *mmap = &process->mmap;
    return -EUNIMPL;
}

static inline int
mmap_region_map_page(
        struct mmap_region *region,
        struct mmap_page *page) 
{
    int res;

    if(page->flags & MMAP_PAGE_MAPPED) {
        dprintk("Page is already mapped flags = %p\n", (uintptr_t)page->flags);
        return 0;
    }

    // Always user by default
    unsigned long vmem_flags = VMEM_REGION_USER;

    if(region->prot_flags & MMAP_PROT_READ)
    {
        vmem_flags |= VMEM_REGION_READ;
    }

    if((region->prot_flags & MMAP_PROT_WRITE))
    {
        if((page->flags & MMAP_PAGE_COPY_ON_WRITE) == 0) {
            vmem_flags |= VMEM_REGION_WRITE;
        } else {
            dprintk("Avoiding mapping mmap page as writable because it is copy-on-write\n");
        }
    }

    if((region->prot_flags & MMAP_PROT_EXEC))
    {
        vmem_flags |= VMEM_REGION_EXEC;
    }

    // No writable exec mappings (should be caught earlier than this)
    DEBUG_ASSERT(!((vmem_flags & VMEM_REGION_EXEC) && (vmem_flags & VMEM_REGION_WRITE)));

    res = vmem_paged_region_map(
            region->mmap->vmem_region,
            page->tree_node.key,
            page->phys_addr,
            1ULL<<page->order,
            vmem_flags);
    if(res) {
        return res;
    }

    page->flags |= MMAP_PAGE_MAPPED;

    return 0;
}

static inline int
mmap_region_unmap_page(
        struct mmap_region *region,
        struct mmap_page *page)
{
    int res;

    if((page->flags & MMAP_PAGE_MAPPED) == 0) {
        return 0;
    }

    res = vmem_paged_region_unmap(
            region->mmap->vmem_region,
            page->tree_node.key,
            1ULL<<page->order);
    if(res) {
        return res;
    } 

    page->flags &= ~MMAP_PAGE_MAPPED;

    return 0;
}

static int
mmap_region_flush_page(
        struct mmap_region *region,
        struct mmap_page *page)
{
    if(page->flags & MMAP_PAGE_ANON) {
        return 0;
    }

    struct file_descriptor *desc = region->desc;
    DEBUG_ASSERT_MSG(desc != NULL, "mmap Region has NULL file descriptor without MMAP_PAGE_NO_SWAP!");

    struct fs_node *node = desc->node; 
    return fs_node_flush_page(node, page->fs_page);
}

// Unmap, and unload the page
static int
mmap_region_reclaim_page(
        struct mmap_region *region,
        struct mmap_page *page)
{
    int res;

    res = mmap_region_unmap_page(region, page);
    if(res) {
        return res;
    }

    int modified;

    // Assume the worst (TODO: actually enable checking page table "dirty" bit)
    if((region->prot_flags & MMAP_PROT_WRITE)) {
        modified = 1;
    } else {
        modified = 0;
    }

    if(page->flags & MMAP_PAGE_ANON) {
        DEBUG_ASSERT(page->fs_page == NULL);
        res = page_free(page->order, page->phys_addr);
        if(res) {
            return res;
        }
    } else {
        DEBUG_ASSERT(page->fs_page != NULL);
        res = fs_node_put_page(
                region->desc->node,
                page->fs_page,
                modified);
        if(res) {
            return res;
        }
    }

    // Our backing memory should be free now

    struct ptree_node *rem = ptree_remove(&region->page_tree, page->tree_node.key);
    DEBUG_ASSERT(rem == &page->tree_node);

    kfree(page);

    return 0;
}

static int
mmap_file_prot_check(
        struct file_descriptor *desc,
        unsigned long prot_flags,
        unsigned long mmap_flags)
{
    if((prot_flags & MMAP_PROT_READ) &&
       (desc->access_flags & FILE_PERM_READ) == 0) {
        eprintk("mmap_file_prot_check: read permission fail!\n");
        return -EPERM;
    }
    if((prot_flags & MMAP_PROT_WRITE) &&
       (desc->access_flags & FILE_PERM_WRITE) == 0)
    {
        if((mmap_flags & MMAP_PRIVATE) &&
           (desc->access_flags & FILE_PERM_READ))
        {
            // This is fine,
            //
            // If we have read permissions, then a user could just
            // create two mappings, one anonymous, and one read-only
            // file backed, then copy the data themselves to get a
            // writable copy.
            //
            // This is just a performance save, and stops use from
            // forcing executables from being opened as "writable"
            // even if all the mappings are PRIVATE, so the actual
            // file never gets written to.
        } else {
            eprintk("mmap_file_prot_check: write permission fail!\n");
            return -EPERM;
        }
    }
    if((prot_flags & MMAP_PROT_EXEC) &&
       (desc->access_flags & FILE_PERM_EXEC) == 0) {
        eprintk("mmap_file_prot_check: exec permission fail!\n");
        return -EPERM;
    }

    return 0;
}

int
mmap_map_region(
        struct process *process,
        fd_t file,
        uintptr_t file_offset,
        uintptr_t mmap_offset,
        size_t size,
        unsigned long prot_flags,
        unsigned long mmap_flags)
{
    int res;

    // syscall_mmap should check these assumptions for user requests,
    // but the kernel might be invoking this function incorrectly
    DEBUG_ASSERT((file == NULL_FD) || (ptr_orderof(file_offset) >= VMEM_MIN_PAGE_ORDER));
    DEBUG_ASSERT(ptr_orderof(mmap_offset) >= VMEM_MIN_PAGE_ORDER);
    DEBUG_ASSERT(ptr_orderof(size) >= VMEM_MIN_PAGE_ORDER);

    struct file_descriptor *desc;

    if((mmap_flags & MMAP_ANON) == 0) {
        desc = file_table_get_descriptor(&process->file_table, file);

        res = mmap_file_prot_check(desc, prot_flags, mmap_flags);
        if(res) {
            goto err1;
        }
    }
    else {
        // This is an anonymous mapping
        desc = NULL;
    }


    struct mmap *mmap = &process->mmap;

    struct mmap_region *region;
    region = kmalloc(sizeof(struct mmap_region));
    if(region == NULL) {
        res = -ENOMEM;
        goto err1;
    }
    memset(region, 0, sizeof(struct mmap_region));

    region->mmap = mmap;
    region->mmap_flags = mmap_flags;
    region->desc = desc;
    region->size = size;
    region->prot_flags = prot_flags;
    region->tree_node.key = mmap_offset;

    spinlock_init(&region->page_tree_lock);
    ptree_init(&region->page_tree);

    uintptr_t end_offset = mmap_offset + size;

    spin_lock(&mmap->lock);

    struct ptree_node *before =
        ptree_get_max_less(&mmap->region_tree, end_offset);
    if(before != NULL) {
        struct mmap_region *before_region =
            container_of(before, struct mmap_region, tree_node);
        uintptr_t before_ending = before->key + before_region->size;
        if(before_ending > mmap_offset) {
            res = -ENXIO;
            goto err3;
        }
    }

    res = ptree_insert(
            &mmap->region_tree,
            &region->tree_node,
            mmap_offset);
    if(res) {
        goto err3;
    }

    spin_unlock(&mmap->lock);
    return 0;

err3:
    spin_unlock(&mmap->lock);
err2:
    kfree(region);
err1:
    if(desc) {
        file_table_put_descriptor(&process->file_table, desc);
    }
err0:
    return res;
}

int
mmap_unmap_region(
        struct process *process,
        uintptr_t mmap_offset)
{
    int res;

    struct mmap *mmap = &process->mmap;

    spin_lock(&mmap->lock);

    struct ptree_node *pnode =
        ptree_get_max_less_or_eq(
                &mmap->region_tree,
                mmap_offset);
    if(pnode == NULL) {
        spin_unlock(&mmap->lock);
        return -ENXIO;
    }

    struct mmap_region *region =
        container_of(pnode, struct mmap_region, tree_node);

    struct file_descriptor *desc = region->desc;

    struct ptree_node *removed =
        ptree_remove(&mmap->region_tree, pnode->key);
    DEBUG_ASSERT(removed == pnode);

    spin_lock(&region->page_tree_lock);

    size_t num_reclaimed = 0;

    struct ptree_node *page_node = ptree_get_first(&region->page_tree);
    while(page_node != NULL)
    {
        struct mmap_page *page =
            container_of(page_node, struct mmap_page, tree_node);

        res = mmap_region_reclaim_page(region, page);
        if(res) {
            spin_unlock(&region->page_tree_lock);
            spin_unlock(&mmap->lock);
            eprintk("mmap_unmap_region: mmap_region_reclaim_page returned %s\n",
                    errnostr(res));
            return res;
        }

        struct ptree_node *next = ptree_get_first(&region->page_tree);
        if(next == page_node) {
            spin_unlock(&region->page_tree_lock);
            spin_unlock(&mmap->lock);
            eprintk("mmap_unmap_region: Failed to reclaim mmap page\n");
            return -EINVAL;
        }
        page_node = next;
        num_reclaimed++;
    }

    dprintk("mmap_unmap_region: reclaimed %lld pages\n", (sll_t)num_reclaimed);
    
    file_table_put_descriptor(&process->file_table, desc);

    spin_unlock(&region->page_tree_lock);
    spin_unlock(&mmap->lock);
    return 0;
}


static int
mmap_region_load_page(
        struct mmap_region *region,
        uintptr_t page_offset,
        struct mmap_page **out)
{
    int res;

    struct fs_page *fs_page = NULL;
    paddr_t paddr = 0;
    order_t order = 0;
    unsigned long page_flags = 0;

    unsigned long mmap_type = region->mmap_flags & 0b11;

    if(mmap_type == MMAP_ANONYMOUS)
    {
        order = VMEM_MIN_PAGE_ORDER;
        res = page_alloc(order, &paddr, 0);
        if(res) {
            return res;
        }
        
        // Clear the page
        void *page_data = (void*)__va(paddr);
        memset(page_data, 0, 1ULL<<order);

        // Align our page offset to the base of the page
        page_offset &= ~((1ULL<<order)-1);

        page_flags |= MMAP_PAGE_ANON;
    }
    else if(mmap_type == MMAP_SHARED || mmap_type == MMAP_PRIVATE) {

        struct file_descriptor *desc = region->desc;
        DEBUG_ASSERT(desc != NULL);
        
        order = fs_node_page_order(region->desc->node);
        if(order < VMEM_MIN_PAGE_ORDER) {
            wprintk("Tried to mmap file with page order %ld, which is too small to mmap! (VMEM_MIN_PAGE_ORDER=%ld)\n",
                    (sl_t)order, (sl_t)VMEM_MIN_PAGE_ORDER);
            return -EINVAL;
        }

        uintptr_t pfn = page_offset >> order;

        // Patch our page offset
        page_offset = pfn << order;

        fs_page = fs_node_get_page(
                desc->node,
                pfn);
        if(fs_page == NULL) {
            return -EINVAL;
        }

        if(mmap_type == MMAP_PRIVATE) {
            page_flags |= MMAP_PAGE_COPY_ON_WRITE;
        }

        paddr = fs_page->paddr;

    } else {
        // This shouldn't be able to reach this function,
        // and should be caught during "mmap_map_region"
        panic("mmap_region_load_page with unknown mmap type! (not MMAP_ANON, MMAP_SHARED or MMAP_PRIVATE)\n");
    }

    struct mmap_page *page = kmalloc(sizeof(struct mmap_page));
    if(page == NULL) {
        if(page_flags & MMAP_PAGE_ANON) {
            page_free(order, paddr);
        }
        return -ENOMEM;
    }
    memset(page, 0, sizeof(struct mmap_page));

    page->order = order;
    page->flags = page_flags;
    page->phys_addr = paddr;
    page->fs_page = fs_page;

    res = ptree_insert(&region->page_tree, &page->tree_node, page_offset);
    if(res) {
        if(page_flags & MMAP_PAGE_ANON) {
            page_free(order, paddr);
        }
        kfree(page);
        return res;
    }

    *out = page;

    return 0;
}

int
mmap_page_do_copy_on_write(
        struct mmap_region *region,
        struct mmap_page *page)
{
    int res;

    dprintk("mmap_page_do_copy_on_write(region=%p, page=%p, page->offset=%p)\n",
            region, page, page->tree_node.key);

    res = mmap_region_unmap_page(region, page);
    if(res) {
        eprintk("mmap_page_do_copy_on_write: mmap_region_unmap_page returned (%s)\n",
                errnostr(res));
        return res;
    }
    // The process tried to write to a "copy-on-write" page
    paddr_t new_page;

    dprintk("unmapped page\n");

    res = page_alloc(page->order, &new_page, 0);
    if(res) {
        eprintk("mmap_page_do_copy_on_write: page_alloc returned %s\n", 
                errnostr(res));
        mmap_region_map_page(region, page);
        return res;
    }

    void *new_data = (void*)__va(new_page);
    void *old_data = (void*)__va(page->phys_addr);

    memcpy(new_data, old_data, 1ULL<<page->order);

    dprintk("copied data\n");

    if((page->flags & MMAP_PAGE_ANON) == 0) {

        dprintk("putting fs_page\n");

        DEBUG_ASSERT(region);
        DEBUG_ASSERT(region->desc);
        DEBUG_ASSERT(region->desc->node);

        struct fs_node *fs_node = region->desc->node;

        DEBUG_ASSERT(page->fs_page);

        res = fs_node_put_page(
                fs_node,
                page->fs_page,
                0); // It can't be dirty, we trapped copy-on-write

        if(res) {
            mmap_region_map_page(region, page);
            page_free(page->order, new_page);
            eprintk("mmap_page_do_copy_on_write: fs_node_put_page returned %s\n",
                    errnostr(res));
            return res; 
        }
        dprintk("put fs_page\n");

    } else {
        panic("mmap_page_do_copy_on_write: MMAP_PAGE_ANON and MMAP_PAGE_COPY_ON_WRITE are both set (Unsupported!)\n");
    }

    page->flags &= ~MMAP_PAGE_COPY_ON_WRITE;
    page->flags |= MMAP_PAGE_ANON;
    page->phys_addr = new_page;

    dprintk("populated page flags\n");

    res = mmap_region_map_page(region, page);
    if(res) {
        // We can potentially survive this, it'll just become an unmapped but
        // loaded anonymous page, and we'll fault again and try to map it,
        // (if it fails then, then we should terminate the process)
        eprintk("mmap_page_do_copy_on_write: during remapping of copy-on-write page, mmap_region_map_page returned %s\n",
                errnostr(res));
    }

    dprintk("mmap_page_do_copy_on_write finished\n");
    return 0;
}

int
mmap_read(
        struct process *process,
        uintptr_t offset,
        void *dst,
        size_t length)
{
    int res;

    struct mmap *mmap = &process->mmap;

    dprintk("mmap_read(pid=%ld, offset=%p, dst=%p, length=0x%llx)\n",
            (sl_t)process->id, offset, dst, (ull_t)length);

    // Overflow checking
    if(~(uintptr_t)(0) - offset < length) {
        eprintk("mmap_read(process=%ld,offset=0x%llx,len=0x%llx) Overflow detected!\n",
                (sl_t)process->id,
                (ull_t)offset,
                (ull_t)length);
        return -EINVAL;
    }

    int irq_flags = spin_lock_irq_save(&mmap->lock);

    if(offset + length > mmap->vmem_region->size) {
        spin_unlock_irq_restore(&mmap->lock, irq_flags);
        return -EINVAL;
    }

    while(length > 0) {

        struct ptree_node *pnode;
        pnode = ptree_get_max_less_or_eq(&mmap->region_tree, offset);

        struct mmap_region *region =
            container_of(pnode, struct mmap_region, tree_node);

        if((pnode == NULL) ||
           (offset >= region->size + pnode->key))
        {
            spin_unlock_irq_restore(&mmap->lock, irq_flags);
            return -EINVAL;
        }

        spin_lock(&region->page_tree_lock);

        if((region->prot_flags & MMAP_PROT_READ) == 0) {
            // The process is not allowed to read this page
            spin_unlock(&region->page_tree_lock);
            spin_unlock_irq_restore(&mmap->lock, irq_flags);
            eprintk("mmap_read(process=%ld,offset=0x%llx,len=0x%llx)"
                    " Page is not Mapped as Readable!\n",
                (sl_t)process->id,
                (ull_t)offset,
                (ull_t)length);
            return -EINVAL;
        }

        // Get or load the page
        pnode = ptree_get_max_less_or_eq(&region->page_tree, offset);
        struct mmap_page *page =
            container_of(pnode, struct mmap_page, tree_node);
        if((pnode == NULL) ||
           (offset >= pnode->key + (1ULL<<page->order))) 
        {
            res = mmap_region_load_page(
                    region,
                    offset - region->tree_node.key,
                    &page);
            if(res) {
                spin_unlock(&region->page_tree_lock);
                spin_unlock_irq_restore(&mmap->lock, irq_flags);
                return res;
            }
        }

        if(page == NULL) {
            spin_unlock(&region->page_tree_lock);
            spin_unlock_irq_restore(&mmap->lock, irq_flags);
            return -EINVAL;
        }

        paddr_t page_paddr = page->phys_addr;
        void *page_data = (void*)__va(page_paddr);

        uintptr_t page_offset = page->tree_node.key;
        size_t page_size = 1ULL << page->order;
        size_t relative_offset = offset - page_offset;
        size_t room_avail = page_size - relative_offset;
        if(length <= room_avail) {
            memcpy(dst, page_data + relative_offset, length);
            length = 0;
        } else {
            memcpy(dst, page_data + relative_offset, room_avail);
            length -= room_avail;
            dst += room_avail;
            offset += room_avail;
        }

        spin_unlock(&region->page_tree_lock);
    }
    
    spin_unlock_irq_restore(&mmap->lock, irq_flags);
    return 0;
}

int
mmap_write(
        struct process *process,
        uintptr_t offset,
        void *src,
        size_t length)
{
    int res;

    struct mmap *mmap = &process->mmap;

    // Overflow checking
    if(~(uintptr_t)(0) - offset < length) {
        return -EINVAL;
    }

    int irq_flags = spin_lock_irq_save(&mmap->lock);

    if(offset + length > mmap->vmem_region->size) {
        spin_unlock_irq_restore(&mmap->lock, irq_flags);
        return -EINVAL;
    }

    while(length > 0) {

        struct ptree_node *pnode;
        pnode = ptree_get_max_less_or_eq(&mmap->region_tree, offset);

        struct mmap_region *region =
            container_of(pnode, struct mmap_region, tree_node);

        if((pnode == NULL) ||
           (offset >= region->size + pnode->key))
        {
            spin_unlock_irq_restore(&mmap->lock, irq_flags);
            return -EINVAL;
        }

        spin_lock(&region->page_tree_lock);

        if((region->prot_flags & MMAP_PROT_WRITE) == 0) {
            // The process is not allowed to write this page
            spin_unlock(&region->page_tree_lock);
            spin_unlock_irq_restore(&mmap->lock, irq_flags);
            eprintk("mmap_write(process=%ld,offset=0x%llx,len=0x%llx)"
                    " Page is not Mapped as Writable!\n",
                (sl_t)process->id,
                (ull_t)offset,
                (ull_t)length);
            return -EINVAL;
        }

        // Get or load the page
        pnode = ptree_get_max_less_or_eq(&region->page_tree, offset);
        struct mmap_page *page =
            container_of(pnode, struct mmap_page, tree_node);
        if((pnode == NULL) ||
           (offset >= pnode->key + (1ULL<<page->order))) 
        {
            res = mmap_region_load_page(
                    region,
                    offset - region->tree_node.key,
                    &page);
            if(res) {
                spin_unlock(&region->page_tree_lock);
                spin_unlock_irq_restore(&mmap->lock, irq_flags);
                return res;
            }
        }

        if(page == NULL) {
            spin_unlock(&region->page_tree_lock);
            spin_unlock_irq_restore(&mmap->lock, irq_flags);
            return -EINVAL;
        }

        if(page->flags & MMAP_PAGE_COPY_ON_WRITE) {
            res = mmap_page_do_copy_on_write(region, page);
            if(res) {
                spin_unlock(&region->page_tree_lock);
                spin_unlock_irq_restore(&mmap->lock, irq_flags);
                return res;
            }
        }
 
        paddr_t page_paddr = page->phys_addr;
        void *page_data = (void*)__va(page_paddr);

        uintptr_t page_offset = page->tree_node.key;
        size_t page_size = 1ULL << page->order;
        size_t relative_offset = offset - page_offset;
        size_t room_avail = page_size - relative_offset;
        if(length <= room_avail) {
            memcpy(page_data + relative_offset, src, length);
            length = 0;
        } else {
            memcpy(page_data + relative_offset, src, room_avail);
            length -= room_avail;
            src += room_avail;
            offset += room_avail;
        }

        spin_unlock(&region->page_tree_lock);
    }

    spin_unlock_irq_restore(&mmap->lock, irq_flags);
    return 0;
}

// Page Fault Handlers

static int
mmap_not_present_page_fault_handler(
        struct mmap *mmap,
        struct mmap_region *region,
        uintptr_t offset)
{
    int res;

    uintptr_t region_end = region->tree_node.key + region->size;
    if(offset >= region_end) {
        goto unhandled;
    }
    
    struct ptree_node *pnode = ptree_get_max_less_or_eq(
            &region->page_tree, offset);

    struct mmap_page *page;
    if(pnode == NULL) {
        res = mmap_region_load_page(
                region,
                offset,
                &page);
        if(res) {
            goto unhandled;
        }
    } else {
        page = container_of(pnode, struct mmap_page, tree_node);
    }

    if(page == NULL) {
        goto unhandled;
    }

    res = mmap_region_map_page(
            region,
            page);
    if(res) {
        goto unhandled;
    }

    return PAGE_FAULT_HANDLED;

unhandled:
    return PAGE_FAULT_UNHANDLED;
}


static int
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
        panic("Kernel attempted to access process mmap region directly! (mmap_offset=%p)\n",
                offset);
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

    if(pf_flags & PF_FLAG_NOT_PRESENT) {
        res = mmap_not_present_page_fault_handler(
                mmap,
                region,
                offset);

        spin_unlock(&region->page_tree_lock);
        spin_unlock_irq_restore(&mmap->lock, irq_flags);
        return res;
    }

    pnode = ptree_get_max_less_or_eq(
            &region->page_tree,
            offset);
    DEBUG_ASSERT(pnode != NULL);

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

