
#include <kanawha/proc/aspace.h>
#include <kanawha/syscall.h>
#include <kanawha/proc/process.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/irq.h>
#include <kanawha/stdint.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/ptree.h>
#include <kanawha/vmem.h>
#include <kanawha/stddef.h>
#include <kanawha/assert.h>
#include <kanawha/proc/process.h>
#include <kanawha/page_alloc.h>
#include <kanawha/vmem.h>
#include <kanawha/fs/node.h>

int
aspace_create(
        size_t size,
        struct process *initial_process)
{
    int res;

    struct aspace *aspace = kmalloc(sizeof(struct aspace));
    if(aspace == NULL) {
        return -ENOMEM;
    }
    memset(aspace, 0, sizeof(struct aspace));

    spinlock_init(&aspace->lock);
    ptree_init(&aspace->region_tree);
    ilist_init(&aspace->process_list);

    aspace->vmem_region =
        vmem_region_create_paged(
                size,
                aspace_page_fault_handler,
                aspace);

    if(aspace->vmem_region == NULL) {
        kfree(aspace);
        return -EINVAL;
    }

    res = aspace_attach(aspace, initial_process);
    if(res) {
        vmem_region_destroy(aspace->vmem_region);
        kfree(aspace);
        return res;
    }

    return 0;
}

int
aspace_attach(
        struct aspace *aspace,
        struct process *process)
{
    int res;

    int irq_flags = spin_lock_irq_save(&aspace->lock);

    process->aspace = aspace;
    ilist_push_tail(&aspace->process_list, &process->aspace_list_node);

    res = vmem_map_map_region(
            process->thread.mem_map,
            aspace->vmem_region,
            0x0);
    if(res) {
        ilist_remove(&aspace->process_list, &process->aspace_list_node);
        process->aspace = NULL;
        spin_unlock_irq_restore(&aspace->lock, irq_flags);
        return res;
    }

    process->aspace_ref = vmem_map_get_region(process->thread.mem_map, 0x0);
    DEBUG_ASSERT(KERNEL_ADDR(process->aspace_ref));

    spin_unlock_irq_restore(&aspace->lock, irq_flags);
    dprintk("Attached ASPACE %p to Process %p\n",aspace,process);
    return 0;
}

int
aspace_deattach(
        struct aspace *aspace,
        struct process *process)
{
    int res;

    int irq_flags = spin_lock_irq_save(&aspace->lock);

    res = vmem_map_unmap_region(
            process->thread.mem_map,
            process->aspace_ref);
    if(res) {
        spin_unlock_irq_restore(&aspace->lock, irq_flags);
        return res;
    }

    ilist_remove(&aspace->process_list, &process->aspace_list_node);
    process->aspace = NULL;

    if(ilist_empty(&aspace->process_list)) {
        // This was the last process to hold a reference to this aspace
        res = vmem_region_destroy(aspace->vmem_region);
        if(res) {
            wprintk("Failed to destroy aspace vmem_region! (err=%s)\n",
                    errnostr(res));
        }
        kfree(aspace);
        
        // Don't unlock the lock just to be extra safe,
        // we'd rather deadlock than use an invalid vmem_region
        return 0;
    }

    spin_unlock_irq_restore(&aspace->lock, irq_flags);
    return 0;

}

int
aspace_region_map_page(
        struct aspace_region *region,
        struct aspace_page *page) 
{
    int res;

    if(page->flags & ASPACE_PAGE_MAPPED) {
        dprintk("aspace_region_map_page: page is already mapped flags = %p\n", (uintptr_t)page->flags);
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
        if((page->flags & ASPACE_PAGE_COPY_ON_WRITE) == 0) {
            vmem_flags |= VMEM_REGION_WRITE;
        } else {
            dprintk("Avoiding mapping aspace page as writable because it is copy-on-write\n");
        }
    }

    if((region->prot_flags & MMAP_PROT_EXEC))
    {
        vmem_flags |= VMEM_REGION_EXEC;
    }

    // No writable exec mappings (should be caught earlier than this)
    DEBUG_ASSERT(!((vmem_flags & VMEM_REGION_EXEC) && (vmem_flags & VMEM_REGION_WRITE)));

    DEBUG_ASSERT(KERNEL_ADDR(region));
    DEBUG_ASSERT(KERNEL_ADDR(region->aspace));
    DEBUG_ASSERT(KERNEL_ADDR(region->aspace->vmem_region));
    res = vmem_paged_region_map(
            region->aspace->vmem_region,
            region->tree_node.key + page->tree_node.key,
            page->phys_addr,
            1ULL<<page->order,
            vmem_flags);
    if(res) {
        eprintk("aspace_region_map_page: vmem_paged_region_map returned %s, region_offset=%p, region_base=%p, offset=%p\n",
                errnostr(res), page->tree_node.key, region->tree_node.key, page->tree_node.key + region->tree_node.key);
        return res;
    }

    page->flags |= ASPACE_PAGE_MAPPED;
    dprintk("aspace_region_map_page: mapped page region-offset=[%p-%p)\n",
            page->tree_node.key, page->tree_node.key + (1ULL<<page->order));

    return 0;
}

static inline int
aspace_region_unmap_page(
        struct aspace_region *region,
        struct aspace_page *page)
{
    int res;

    if((page->flags & ASPACE_PAGE_MAPPED) == 0) {
        return 0;
    }

    res = vmem_paged_region_unmap(
            region->aspace->vmem_region,
            region->tree_node.key + page->tree_node.key,
            1ULL<<page->order);
    if(res) {
        return res;
    } 

    page->flags &= ~ASPACE_PAGE_MAPPED;

    return 0;
}

static int
aspace_region_flush_page(
        struct aspace_region *region,
        struct aspace_page *page)
{
    unsigned long aspace_type = page->flags & 0b11;
    if(aspace_type == ASPACE_PAGE_ANON) {
        return 0;
    }

    struct fs_node *node = region->fs_node; 
    return fs_node_flush_page(node, page->fs_page);
}

// Unmap, and unload the page
static int
aspace_region_reclaim_page(
        struct aspace_region *region,
        struct aspace_page *page)
{
    int res;

    res = aspace_region_unmap_page(region, page);
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

    if(page->flags & ASPACE_PAGE_ANON) {
        DEBUG_ASSERT(page->fs_page == NULL);
        res = page_free(page->order, page->phys_addr);
        if(res) {
            return res;
        }
    } else {
        DEBUG_ASSERT(KERNEL_ADDR(page->fs_page));
        res = fs_node_put_page(
                region->fs_node,
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
aspace_file_prot_check(
        struct file *desc,
        unsigned long prot_flags,
        unsigned long aspace_flags)
{
    unsigned long aspace_type = aspace_flags & 0b11;

    if((prot_flags & MMAP_PROT_READ) &&
       (desc->access_flags & FILE_PERM_READ) == 0) {
        eprintk("aspace_file_prot_check: read permission fail!\n");
        return -EPERM;
    }
    if((prot_flags & MMAP_PROT_WRITE) &&
       (desc->access_flags & FILE_PERM_WRITE) == 0)
    {
        if((aspace_type == MMAP_PRIVATE) &&
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
            eprintk("aspace_file_prot_check: write permission fail!\n");
            return -EPERM;
        }
    }
    if((prot_flags & MMAP_PROT_EXEC) &&
       (desc->access_flags & FILE_PERM_EXEC) == 0) {
        eprintk("aspace_file_prot_check: exec permission fail!\n");
        return -EPERM;
    }

    return 0;
}

// Needs the aspace->lock to be held,
// and set's region->tree_node.key to a valid aspace_offset
static int
__aspace_locked_hint_offset(
        struct aspace *aspace,
        struct aspace_region *region,
        uintptr_t hint_offset,
        size_t size)
{
    // TODO: Actually take the hint into account

    size_t aspace_size = aspace->vmem_region->size;

    if(size >= aspace_size) {
        return -ENOMEM;
    }

    struct ptree_node *before_node;
    before_node = ptree_get_first(&aspace->region_tree);

    // If there are no regions at all, we will map at "midway"
    // (Roughly in the middle of user-memory)
    uintptr_t midway = aspace->vmem_region->size / 2;
    midway &= ~((1ULL<<VMEM_MIN_PAGE_ORDER)-1);
    uintptr_t cur_offset = midway;

    while(before_node) {
        struct aspace_region *before_region =
            container_of(before_node, struct aspace_region, tree_node);

        cur_offset = before_node->key + before_region->size;

        if((aspace_size - size) < cur_offset) {
            // Would run off the end of user memory
            return -ENOMEM;
        }

        uintptr_t cur_end = cur_offset + size;

        struct ptree_node *after_node = ptree_get_next(before_node);
        if(after_node == NULL) {
            break;
        }

        if(cur_end > after_node->key) {
            // Not enough room between the regions
            before_node = after_node;
            continue;
        }

        // We can fit between the two regions
        region->tree_node.key = cur_offset;
        return 0;
    }

    // We reached the end, there is no region after "cur_offset"
    if((aspace_size - size) < cur_offset) {
        // Not enough room before the end of user-memory
        return -ENOMEM;
    }

    region->tree_node.key = cur_offset;
    return 0;
}

int
aspace_map_region(
        struct process *process,
        fd_t file,
        uintptr_t file_offset,
        uintptr_t *hint_offset,
        size_t size,
        unsigned long prot_flags,
        unsigned long aspace_flags)
{
    int res;

    // syscall_aspace should check these assumptions for user requests,
    // but the kernel might be invoking this function incorrectly
    DEBUG_ASSERT(size > 0);
    DEBUG_ASSERT(ptr_orderof(size) >= VMEM_MIN_PAGE_ORDER);

    struct fs_node *fs_node;

    unsigned long aspace_type = aspace_flags & 0b11;

    if(aspace_type != MMAP_ANON) {
        struct file *desc =
            file_table_get_file(process->file_table, process, file);

        res = aspace_file_prot_check(desc, prot_flags, aspace_flags);
        if(res) {
            file_table_put_file(process->file_table, process, desc);
            goto err0;
        }

        res = fs_node_get(desc->path->fs_node);
        if(res) {
            file_table_put_file(process->file_table, process, desc);
            goto err0;
        }
        fs_node = desc->path->fs_node;

        file_table_put_file(process->file_table, process, desc);
    }
    else {
        // This is an anonymous mapping
        fs_node = NULL;
    }


    struct aspace *aspace = process->aspace;
    DEBUG_ASSERT(KERNEL_ADDR(aspace));

    struct aspace_region *region;
    region = kmalloc(sizeof(struct aspace_region));
    if(region == NULL) {
        res = -ENOMEM;
        goto err1;
    }
    memset(region, 0, sizeof(struct aspace_region));

    region->aspace = aspace;
    region->mmap_flags = aspace_flags;
    region->fs_node = fs_node;
    region->size = size;
    region->prot_flags = prot_flags;
    region->file_offset = file_offset;

    spinlock_init(&region->page_tree_lock);
    ptree_init(&region->page_tree);

    spin_lock(&aspace->lock);

    // This will find us a valid offset
    res = __aspace_locked_hint_offset(
            aspace,
            region,
            *hint_offset,
            size);
    if(res) {
        goto err3;
    }

    *hint_offset = region->tree_node.key;

    res = ptree_insert(
            &aspace->region_tree,
            &region->tree_node,
            region->tree_node.key);
    if(res) {
        eprintk("__aspace_locked_hint_offset returned an offset=%p which could not be inserted! (err=%s)\n",
                *hint_offset, errnostr(res));
        goto err3;
    }

    dprintk("aspace_map_region_exact mapped region [%p-%p)\n",
            region->tree_node.key,
            region->tree_node.key + region->size);

    spin_unlock(&aspace->lock);
    return 0;

err3:
    spin_unlock(&aspace->lock);
err2:
    kfree(region);
err1:
    if(fs_node) {
        fs_node_put(fs_node);
    }
err0:
    return res;
}

int
aspace_map_region_exact(
        struct process *process,
        fd_t file,
        uintptr_t file_offset,
        uintptr_t aspace_offset,
        size_t size,
        unsigned long prot_flags,
        unsigned long aspace_flags)
{
    int res;

    // syscall_aspace should check these assumptions for user requests,
    // but the kernel might be invoking this function incorrectly
    DEBUG_ASSERT(ptr_orderof(aspace_offset) >= VMEM_MIN_PAGE_ORDER);
    DEBUG_ASSERT(ptr_orderof(size) >= VMEM_MIN_PAGE_ORDER);

    struct fs_node *fs_node;

    unsigned long aspace_type = aspace_flags & 0b11;

    if(aspace_type != MMAP_ANON) {
        struct file *desc =
            file_table_get_file(process->file_table, process, file);

        res = aspace_file_prot_check(desc, prot_flags, aspace_flags);
        if(res) {
            file_table_put_file(process->file_table, process, desc);
            goto err0;
        }

        res = fs_node_get(desc->path->fs_node);
        if(res) {
            file_table_put_file(process->file_table, process, desc);
            goto err0;
        }
        fs_node = desc->path->fs_node;

        file_table_put_file(process->file_table, process, desc);
    }
    else {
        // This is an anonymous mapping
        fs_node = NULL;
    }


    struct aspace *aspace = process->aspace;
    DEBUG_ASSERT(KERNEL_ADDR(aspace));

    struct aspace_region *region;
    region = kmalloc(sizeof(struct aspace_region));
    if(region == NULL) {
        res = -ENOMEM;
        goto err1;
    }
    memset(region, 0, sizeof(struct aspace_region));

    region->aspace = aspace;
    region->mmap_flags = aspace_flags;
    region->fs_node = fs_node;
    region->size = size;
    region->prot_flags = prot_flags;
    region->file_offset = file_offset;
    region->tree_node.key = aspace_offset;

    spinlock_init(&region->page_tree_lock);
    dprintk("aspace_region page_tree_init region=%p [%p-%p)\n",
            region,
            region->tree_node.key,
            region->tree_node.key + region->size);
    ptree_init(&region->page_tree);

    uintptr_t end_offset = aspace_offset + size;

    spin_lock(&aspace->lock);

    // We need to check that this mapping doesn't conflict
    struct ptree_node *before =
        ptree_get_max_less(&aspace->region_tree, end_offset);
    if(before != NULL) {
        struct aspace_region *before_region =
            container_of(before, struct aspace_region, tree_node);
        uintptr_t before_ending = before->key + before_region->size;
        if(before_ending > aspace_offset) {
            eprintk("PID(%ld) aspace request [%p-%p) overlaps mapping [%p-%p)\n",
                   (sl_t)process->id,
                   aspace_offset,
                   end_offset,
                   before->key,
                   before_ending
                   );
            res = -EALREADY;
            goto err3;
        }
    }

    dprintk("aspace_map_region_exact mapped region [%p-%p)\n",
            region->tree_node.key,
            region->tree_node.key + region->size);

    res = ptree_insert(
            &aspace->region_tree,
            &region->tree_node,
            aspace_offset);
    if(res) {
        goto err3;
    }

    spin_unlock(&aspace->lock);
    return 0;

err3:
    spin_unlock(&aspace->lock);
err2:
    kfree(region);
err1:
    if(fs_node) {
        fs_node_put(fs_node);
    }
err0:
    return res;
}

int
aspace_unmap_region(
        struct process *process,
        uintptr_t aspace_offset)
{
    int res;

    struct aspace *aspace = process->aspace;
    DEBUG_ASSERT(KERNEL_ADDR(aspace));

    spin_lock(&aspace->lock);

    struct ptree_node *pnode =
        ptree_get_max_less_or_eq(
                &aspace->region_tree,
                aspace_offset);
    if(pnode == NULL) {
        spin_unlock(&aspace->lock);
        return -ENXIO;
    }

    struct aspace_region *region =
        container_of(pnode, struct aspace_region, tree_node);

    if(aspace_offset >= (region->tree_node.key + region->size)) {
        spin_unlock(&aspace->lock);
        return -ENXIO;
    }

    struct fs_node *fs_node = region->fs_node;

    dprintk("aspace_unmap_region: removing region [%p-%p)\n",
            region->tree_node.key, region->tree_node.key + region->size
            );

    struct ptree_node *removed =
        ptree_remove(&aspace->region_tree, pnode->key);
    DEBUG_ASSERT(removed == pnode);

    spin_lock(&region->page_tree_lock);

    size_t num_reclaimed = 0;

    struct ptree_node *page_node = ptree_get_first(&region->page_tree);
    while(page_node != NULL)
    {
        struct aspace_page *page =
            container_of(page_node, struct aspace_page, tree_node);

        res = aspace_region_reclaim_page(region, page);
        if(res) {
            spin_unlock(&region->page_tree_lock);
            spin_unlock(&aspace->lock);
            eprintk("aspace_unmap_region: aspace_region_reclaim_page returned %s\n",
                    errnostr(res));
            return res;
        }

        struct ptree_node *next = ptree_get_first(&region->page_tree);
        if(next == page_node) {
            spin_unlock(&region->page_tree_lock);
            spin_unlock(&aspace->lock);
            eprintk("aspace_unmap_region: Failed to reclaim aspace page\n");
            return -EINVAL;
        }
        page_node = next;
        num_reclaimed++;
    }

    dprintk("aspace_unmap_region: reclaimed %lld pages\n", (sll_t)num_reclaimed);
   
    if(fs_node) {
        fs_node_put(fs_node);
    }

    spin_unlock(&region->page_tree_lock);
    spin_unlock(&aspace->lock);
    return 0;
}


int
aspace_region_load_page(
        struct aspace_region *region,
        uintptr_t page_offset,
        struct aspace_page **out)
{
    int res;

    struct fs_page *fs_page = NULL;
    void __phys * paddr = 0;
    order_t order = 0;
    unsigned long page_flags = 0;

    unsigned long aspace_type = region->mmap_flags & 0b11;

    if(aspace_type == MMAP_ANON)
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

        page_flags |= ASPACE_PAGE_ANON;
    }
    else if(aspace_type == MMAP_SHARED || aspace_type == MMAP_PRIVATE) {

        DEBUG_ASSERT_MSG(
                KERNEL_ADDR(region->fs_node),
                "MMAP_SHARED or MMAP_PRIVATE region has NULL fs_node! region->aspace_flags=0x%lx, region_offset=%p",
                region->mmap_flags, region->tree_node.key);
        
        res = fs_node_page_order(region->fs_node, &order);
        if(res) {
            return res;
        }
        if(order < VMEM_MIN_PAGE_ORDER) {
            wprintk("Tried to aspace file with page order %ld, which is too small to aspace! (VMEM_MIN_PAGE_ORDER=%ld)\n",
                    (sl_t)order, (sl_t)VMEM_MIN_PAGE_ORDER);
            return -EINVAL;
        }

        uintptr_t pfn = page_offset >> order;

        // Patch our page offset
        page_offset = pfn << order;

        // Add our region file offset
        if(ptr_orderof(region->file_offset) < order)
        {
            eprintk("region->file_offset is not aligned to the file page size! (file_offset=%p, page_order=%ld\n",
                    region->file_offset, (sl_t)order);
            return -EINVAL;
        }

        pfn += (region->file_offset >> order);

        fs_page = fs_node_get_page(
                region->fs_node,
                pfn,
                FS_NODE_GET_PAGE_MAY_CREATE);
        if(fs_page == NULL) {
            return -EINVAL;
        }

        if(aspace_type == MMAP_PRIVATE) {
            page_flags |= ASPACE_PAGE_COPY_ON_WRITE;
        }

        paddr = fs_page->paddr;

    } else {
        // This shouldn't be able to reach this function,
        // and should be caught during "aspace_map_region"
        panic("aspace_region_load_page with unknown aspace type! (not MMAP_ANON, MMAP_SHARED or MMAP_PRIVATE)\n");
    }

    struct aspace_page *page = kmalloc(sizeof(struct aspace_page));
    if(page == NULL) {
        if(page_flags & ASPACE_PAGE_ANON) {
            page_free(order, paddr);
        }
        else {
            fs_node_put_page(region->fs_node, page->fs_page, 0);
        }
        return -ENOMEM;
    }
    memset(page, 0, sizeof(struct aspace_page));

    page->order = order;
    page->flags = page_flags;
    page->phys_addr = paddr;
    page->fs_page = fs_page;

    DEBUG_ASSERT(ptr_orderof(page->phys_addr) >= VMEM_MIN_PAGE_ORDER);

    dprintk("aspace_region page_tree insert: region=%p, page=%p, page->region_offset=%p, page->order=%ld\n",
            region, page, page->tree_node.key, page->order);
    res = ptree_insert(&region->page_tree, &page->tree_node, page_offset);
    if(res) {
        if(page_flags & ASPACE_PAGE_ANON) {
            page_free(order, paddr);
        } else {
            fs_node_put_page(region->fs_node, page->fs_page, 0);
        }
        kfree(page);
        return res;
    }

    *out = page;

    return 0;
}

int
aspace_page_do_copy_on_write(
        struct aspace_region *region,
        struct aspace_page *page)
{
    int res;

    dprintk("aspace_page_do_copy_on_write(region=%p, page=%p, page->offset=%p)\n",
            region, page, page->tree_node.key);

    res = aspace_region_unmap_page(region, page);
    if(res) {
        eprintk("aspace_page_do_copy_on_write: aspace_region_unmap_page returned (%s)\n",
                errnostr(res));
        return res;
    }
    // The process tried to write to a "copy-on-write" page
    void __phys * new_page;

    dprintk("unmapped page\n");

    res = page_alloc(page->order, &new_page, 0);
    if(res) {
        eprintk("aspace_page_do_copy_on_write: page_alloc returned %s\n", 
                errnostr(res));
        aspace_region_map_page(region, page);
        return res;
    }

    void *new_data = (void*)__va(new_page);
    void *old_data = (void*)__va(page->phys_addr);

    memcpy(new_data, old_data, 1ULL<<page->order);

    dprintk("copied data\n");

    if((page->flags & ASPACE_PAGE_ANON) == 0) {

        dprintk("putting fs_page\n");

        DEBUG_ASSERT(KERNEL_ADDR(region));
        DEBUG_ASSERT(KERNEL_ADDR(region->fs_node));

        struct fs_node *fs_node = region->fs_node;

        DEBUG_ASSERT(KERNEL_ADDR(page->fs_page));

        res = fs_node_put_page(
                fs_node,
                page->fs_page,
                0); // It can't be dirty, we trapped copy-on-write

        if(res) {
            aspace_region_map_page(region, page);
            page_free(page->order, new_page);
            eprintk("aspace_page_do_copy_on_write: fs_node_put_page returned %s\n",
                    errnostr(res));
            return res; 
        }
        dprintk("put fs_page\n");

    } else {
        panic("aspace_page_do_copy_on_write: ASPACE_PAGE_ANON and ASPACE_PAGE_COPY_ON_WRITE are both set (Unsupported!)\n");
    }

    page->flags &= ~ASPACE_PAGE_COPY_ON_WRITE;
    page->flags |= ASPACE_PAGE_ANON;
    page->phys_addr = new_page;

    dprintk("populated page flags\n");

    res = aspace_region_map_page(region, page);
    if(res) {
        // We can potentially survive this, it'll just become an unmapped but
        // loaded anonymous page, and we'll fault again and try to map it,
        // (if it fails then, then we should terminate the process)
        eprintk("aspace_page_do_copy_on_write: during remapping of copy-on-write page, aspace_region_map_page returned %s\n",
                errnostr(res));
    }

    dprintk("aspace_page_do_copy_on_write finished\n");
    return 0;
}

int
aspace_read(
        struct process *process,
        uintptr_t offset,
        void *dst,
        size_t length)
{
    int res;

    struct aspace *aspace = process->aspace;
    DEBUG_ASSERT(KERNEL_ADDR(aspace));

    dprintk("aspace_read(pid=%ld, offset=%p, dst=%p, length=0x%llx)\n",
            (sl_t)process->id, offset, dst, (ull_t)length);

    // Overflow checking
    if(~(uintptr_t)(0) - offset < length) {
        eprintk("aspace_read(process=%ld,offset=0x%llx,len=0x%llx) Overflow detected!\n",
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

        if((region->prot_flags & MMAP_PROT_READ) == 0) {
            // The process is not allowed to read this page
            spin_unlock(&region->page_tree_lock);
            spin_unlock_irq_restore(&aspace->lock, irq_flags);
            eprintk("aspace_read(process=%ld,offset=0x%llx,len=0x%llx)"
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
aspace_write(
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

        if((region->prot_flags & MMAP_PROT_WRITE) == 0) {
            // The process is not allowed to write this page
            spin_unlock(&region->page_tree_lock);
            spin_unlock_irq_restore(&aspace->lock, irq_flags);
            eprintk("aspace_write(process=%ld,offset=0x%llx,len=0x%llx)"
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
aspace_user_strlen(
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

    dprintk("aspace_user_strlen: PID(%ld), aspace=%p, offset=0x%lx, max=0x%lx\n",
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
            spin_unlock_irq_restore(&aspace->lock, irq_flags);
            return -EINVAL;
        }

        DEBUG_ASSERT(ptr_orderof(region->tree_node.key) >= VMEM_MIN_PAGE_ORDER);
        DEBUG_ASSERT(ptr_orderof(region->tree_node.key) <= 64);
        DEBUG_ASSERT(region->size > 0);

        dprintk("region=%p [%p-%p)\n", region, region->tree_node.key, region->tree_node.key + region->size);

        spin_lock(&region->page_tree_lock);

        size_t region_offset = offset - region->tree_node.key;

        if((region->prot_flags & MMAP_PROT_READ) == 0) {
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
            dprintk("loading page (offset=%p)\n", region_offset);
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
            dprintk("already had page (offset=%p)\n", region_offset);
        }

        struct ptree_node *iter = ptree_get_first(&region->page_tree);
        for(; iter != NULL; iter = ptree_get_next(iter)) {
            struct aspace_page *iter_page =
                container_of(iter, struct aspace_page, tree_node);
            dprintk("page=%p, phys_addr=%p, order=%ld, fs_page=%p\n",
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

// Page Fault Handlers

int
aspace_not_present_page_fault_handler(
        struct aspace *aspace,
        struct aspace_region *region,
        uintptr_t region_offset)
{
    int res;

    dprintk("aspace_not_present_page_fault_handler: region->base=%p, region_offset=%p, region->file_offset=%p\n",
            region->tree_node.key, region_offset, region->file_offset);

    if(region_offset >= region->size) {
        goto unhandled;
    }
    
    struct ptree_node *pnode = ptree_get_max_less_or_eq(
            &region->page_tree, region_offset);

    struct aspace_page *page =
        container_of(pnode, struct aspace_page, tree_node);

    if(pnode == NULL ||
       ((pnode->key + (1ULL<<page->order)) <= region_offset)) {
        res = aspace_region_load_page(
                region,
                region_offset,
                &page);
        if(res) {
            goto unhandled;
        }
    }
    dprintk("aspace_not_present_page_fault_handler: page=%p\n",
            page);

    if(page == NULL) {
        goto unhandled;
    }

    res = aspace_region_map_page(
            region,
            page);
    if(res) {
        goto unhandled;
    }

    dprintk("aspace_not_present_page_fault_handler: mapped page!\n");
    return PAGE_FAULT_HANDLED;

unhandled:
    return PAGE_FAULT_UNHANDLED;
}


int
aspace_page_fault_handler(
        struct vmem_region_ref *ref,
        uintptr_t offset,
        unsigned long pf_flags,
        void *priv_state)
{
    dprintk("aspace_page_fault_handler offset=%p, pf_flags=0x%llx\n",
            offset, (ull_t)pf_flags);
    struct aspace *aspace = priv_state;

    if((pf_flags & PF_FLAG_USERMODE) == 0) {
        eprintk("Kernel attempted to access process aspace region directly! (aspace_offset=%p)\n",
                offset);
        return PAGE_FAULT_UNHANDLED;
    }

    int res;
    int irq_flags = spin_lock_irq_save(&aspace->lock);

    struct ptree_node *pnode;
    pnode = ptree_get_max_less_or_eq(&aspace->region_tree, offset);
    if(pnode == NULL) {
        spin_unlock_irq_restore(&aspace->lock, irq_flags);
        return PAGE_FAULT_UNHANDLED;
    }

    struct aspace_region *region =
        container_of(pnode, struct aspace_region, tree_node);

    spin_lock(&region->page_tree_lock);

    uintptr_t region_offset = offset - region->tree_node.key;

    if(pf_flags & PF_FLAG_NOT_PRESENT) {
        res = aspace_not_present_page_fault_handler(
                aspace,
                region,
                region_offset);

        spin_unlock(&region->page_tree_lock);
        spin_unlock_irq_restore(&aspace->lock, irq_flags);
        return res;
    }

    pnode = ptree_get_max_less_or_eq(
            &region->page_tree,
            region_offset);
    DEBUG_ASSERT(KERNEL_ADDR(pnode));

    struct aspace_page *page =
        container_of(pnode, struct aspace_page, tree_node);

    if((page->flags & ASPACE_PAGE_COPY_ON_WRITE)&&(pf_flags & PF_FLAG_WRITE))
    {
        res = aspace_page_do_copy_on_write(region, page); 
        if(res) {
            spin_unlock(&region->page_tree_lock);
            spin_unlock_irq_restore(&aspace->lock, irq_flags);
            return PAGE_FAULT_UNHANDLED;
        }

        spin_unlock(&region->page_tree_lock);
        spin_unlock_irq_restore(&aspace->lock, irq_flags);
        return PAGE_FAULT_HANDLED;
    }

    spin_unlock(&region->page_tree_lock);
    spin_unlock_irq_restore(&aspace->lock, irq_flags);
    return PAGE_FAULT_UNHANDLED;
}
