
#include <kanawha/syscall.h>
#include <kanawha/proc/process.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/irq.h>
#include <kanawha/types.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/ptree.h>
#include <kanawha/vmem.h>
#include <kanawha/stddef.h>
#include <kanawha/assert.h>
#include <kanawha/proc/process.h>
#include <kanawha/page_alloc.h>
#include <kanawha/proc/mmap.h>
#include <kanawha/vmem.h>
#include <kanawha/fs/node.h>
#include <kanawha/printk.h>

static int
mmap_unmap_region_lockless(
	struct mmap *mmap,
	struct mmap_region *region);

int
mmap_create(
        size_t size,
        struct process *initial_process)
{
    int res;

    struct mmap *mmap = kzmalloc(sizeof(struct mmap), KM_KERNEL);
    if(mmap == NULL) {
        return -ENOMEM;
    }

    spinlock_init(&mmap->lock);
    ptree_init(&mmap->region_tree);
    ilist_init(&mmap->process_list);

    mmap->vmem_region =
        vmem_region_create_paged(
                size,
                mmap_page_fault_handler,
                mmap);

    if(mmap->vmem_region == NULL) {
        kfree(mmap);
        return -EINVAL;
    }

    res = mmap_attach(mmap, initial_process);
    if(res) {
        vmem_region_destroy(mmap->vmem_region);
        kfree(mmap);
        return res;
    }

    return 0;
}

int
mmap_attach(
        struct mmap *mmap,
        struct process *process)
{
    int res;

    int irq_flags = spin_lock_irq_save(&mmap->lock);

    process->mmap = mmap;
    ilist_push_tail(&mmap->process_list, &process->mmap_list_node);

    res = vmem_map_map_region(
            process->thread.mem_map,
            mmap->vmem_region,
            0x0);
    if(res) {
        ilist_remove(&mmap->process_list, &process->mmap_list_node);
        process->mmap = NULL;
        spin_unlock_irq_restore(&mmap->lock, irq_flags);
        return res;
    }

    process->mmap_ref = vmem_map_get_region(process->thread.mem_map, 0x0);
    DEBUG_ASSERT(KERNEL_ADDR(process->mmap_ref));

    spin_unlock_irq_restore(&mmap->lock, irq_flags);
    dprintk("Attached MMAP %p to Process %p\n",mmap,process);
    return 0;
}

int
mmap_deattach(
        struct mmap *mmap,
        struct process *process)
{
    int res;

    int irq_flags = spin_lock_irq_save(&mmap->lock);

    res = vmem_map_unmap_region(
            process->thread.mem_map,
            process->mmap_ref);
    if(res) {
        spin_unlock_irq_restore(&mmap->lock, irq_flags);
        return res;
    }

    ilist_remove(&mmap->process_list, &process->mmap_list_node);
    process->mmap = NULL;

    if(ilist_empty(&mmap->process_list)) {

	dprintk("Destroying MMAP\n");

	while(1) {
	    struct ptree_node *region_node = ptree_get_first(&mmap->region_tree);
	    if(region_node == NULL) {
		break;
	    }
	    res = mmap_unmap_region_lockless(
		    mmap,
		    container_of(region_node, struct mmap_region, tree_node));
	    if(res) {
		eprintk("Failed to unmap region on mmap destruction! (err=%s)\n",
			errnostr(res));
	    }
	}

        // This was the last process to hold a reference to this mmap
        res = vmem_region_destroy(mmap->vmem_region);
        if(res) {
            wprintk("Failed to destroy mmap vmem_region! (err=%s)\n",
                    errnostr(res));
        }

        kfree(mmap);
        
        // Don't unlock the lock just to be extra safe,
        // we'd rather deadlock than use an invalid vmem_region
        enable_restore_irqs(irq_flags);
        return 0;
    }

    spin_unlock_irq_restore(&mmap->lock, irq_flags);
    return 0;
}

int
mmap_region_map_page(
        struct mmap_region *region,
        struct mmap_page *page) 
{
    int res;

    if(page->flags & MMAP_PAGE_MAPPED) {
        dprintk("mmap_region_map_page: page is already mapped flags = %p\n", (uintptr_t)page->flags);
        return 0;
    }

    // Always user by default
    unsigned long vmem_flags = VMEM_REGION_USER;

    if(region->mmap_flags & MMAP_PROT_READ)
    {
        vmem_flags |= VMEM_REGION_READ;
    }

    if((region->mmap_flags & MMAP_PROT_WRITE))
    {
        if((page->flags & MMAP_PAGE_COPY_ON_WRITE) == 0) {
            vmem_flags |= VMEM_REGION_WRITE;
        } else {
            dprintk("Avoiding mapping mmap page as writable because it is copy-on-write\n");
        }
    }

    if((region->mmap_flags & MMAP_PROT_EXEC))
    {
        vmem_flags |= VMEM_REGION_EXEC;
    }

    // No writable exec mappings (should be caught earlier than this)
    DEBUG_ASSERT(!((vmem_flags & VMEM_REGION_EXEC) && (vmem_flags & VMEM_REGION_WRITE)));

    DEBUG_ASSERT(KERNEL_ADDR(region));
    DEBUG_ASSERT(KERNEL_ADDR(region->mmap));
    DEBUG_ASSERT(KERNEL_ADDR(region->mmap->vmem_region));
    res = vmem_paged_region_map(
            region->mmap->vmem_region,
            region->tree_node.key + page->tree_node.key,
            page->phys_addr,
            1ULL<<page->order,
            vmem_flags);
    if(res) {
        eprintk("mmap_region_map_page: vmem_paged_region_map returned %s, region_offset=%p, region_base=%p, offset=%p\n",
                errnostr(res), page->tree_node.key, region->tree_node.key, page->tree_node.key + region->tree_node.key);
        return res;
    }

    page->flags |= MMAP_PAGE_MAPPED;
    dprintk("mmap_region_map_page: mapped page region-offset=[%p-%p)\n",
            page->tree_node.key, page->tree_node.key + (1ULL<<page->order));

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
            region->tree_node.key + page->tree_node.key,
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
    unsigned long mmap_type = page->flags & 0b11;
    if(mmap_type == MMAP_PAGE_ANON) {
        return 0;
    }

    struct fs_node *node = region->fs_node; 
    return fs_node_flush_page(
            node,
            page->tree_node.key,
            0,
            page->phys_addr);
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
    if((region->mmap_flags & MMAP_PROT_WRITE)) {
        modified = 1;
    } else {
        modified = 0;
    }

    if(page->flags & MMAP_PAGE_ANON) {
        int can_free = 1;
        if(page->flags & MMAP_PAGE_COPY_ON_WRITE) {
            atomic_t *sharing_level = page->anon_sharing_level;
            atomic_t new_level = atomic_fetch_dec(sharing_level)-1;
            if(new_level != 0) {
                can_free = 0;
            } else {
                kfree(page->anon_sharing_level);
            }
        }
        if(can_free) {
            res = page_free(page->order, page->phys_addr);
            if(res) {
                return res;
            }
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
mmap_file_prot_check(
        struct file *desc,
        unsigned long mmap_flags)
{
    unsigned long mmap_type = (mmap_flags & MMAP_FLAGS_TYPE_MASK);

    if((mmap_flags & MMAP_PROT_READ) &&
       (desc->access_flags & FILE_PERM_READ) == 0) {
        eprintk("mmap_file_prot_check: read permission fail!\n");
        return -EPERM;
    }
    if((mmap_flags & MMAP_PROT_WRITE) &&
       (desc->access_flags & FILE_PERM_WRITE) == 0)
    {
        if((mmap_type == MMAP_PRIVATE) &&
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
    if((mmap_flags & MMAP_PROT_EXEC) &&
       (desc->access_flags & FILE_PERM_EXEC) == 0) {
        eprintk("mmap_file_prot_check: exec permission fail!\n");
        return -EPERM;
    }

    return 0;
}

// Needs the mmap->lock to be held,
// and set's region->tree_node.key to a valid mmap_offset
static int
__mmap_locked_hint_offset(
        struct mmap *mmap,
        struct mmap_region *region,
        uintptr_t hint_offset,
        size_t size)
{
    // TODO: Actually take the hint into account

    size_t mmap_size = mmap->vmem_region->size;

    if(size >= mmap_size) {
        wprintk("Process MMAP requested too large of a region!\n");
        return -ENOMEM;
    }

    struct ptree_node *before_node;
    before_node = ptree_get_first(&mmap->region_tree);

    // If there are no regions at all, we will map at "midway"
    // (Roughly in the middle of user-memory)
    uintptr_t midway = mmap->vmem_region->size / 2;
    midway &= ~((1ULL<<VMEM_MIN_PAGE_ORDER)-1);
    uintptr_t cur_offset = midway;

    while(before_node) {
        struct mmap_region *before_region =
            container_of(before_node, struct mmap_region, tree_node);

        cur_offset = before_node->key + before_region->size;

        if((mmap_size - size) < cur_offset) {
            // Would run off the end of user memory
            wprintk("Process MMAP ran out of virtual memory!\n");
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
    if((mmap_size - size) < cur_offset) {
        // Not enough room before the end of user-memory
        return -ENOMEM;
    }

    region->tree_node.key = cur_offset;
    return 0;
}

int
mmap_map_region(
        struct process *process,
        fd_t file,
        uintptr_t file_offset,
        uintptr_t *hint_offset,
        size_t size,
        unsigned long mmap_flags)
{
    int res;

    // syscall_mmap should check these assumptions for user requests,
    // but the kernel might be invoking this function incorrectly
    DEBUG_ASSERT(size > 0);
    DEBUG_ASSERT(ptr_orderof(size) >= VMEM_MIN_PAGE_ORDER);

    struct fs_node *fs_node;

    unsigned long mmap_type = mmap_flags & 0b11;

    if(mmap_type != MMAP_ANON) {
        struct file *desc =
            file_table_get_file(process->file_table, process, file);

        res = mmap_file_prot_check(desc, mmap_flags);
        if(res) {
            file_table_put_file(process->file_table, process, desc);
            goto err0;
        }

        fs_node = fs_path_get_fs_node(desc->path);
        if(fs_node == NULL) {
            file_table_put_file(process->file_table, process, desc);
            res = -EINVAL;
            goto err0;
        }

        res = fs_node_get(fs_node);
        if(res) {
            file_table_put_file(process->file_table, process, desc);
            goto err0;
        }

        file_table_put_file(process->file_table, process, desc);
    }
    else {
        // This is an anonymous mapping
        fs_node = NULL;
    }


    struct mmap *mmap = process->mmap;
    DEBUG_ASSERT(KERNEL_ADDR(mmap));

    struct mmap_region *region;
    region = kzmalloc(sizeof(struct mmap_region), KM_KERNEL);
    if(region == NULL) {
        res = -ENOMEM;
        goto err1;
    }

    region->mmap = mmap;
    region->mmap_flags = mmap_flags;
    region->fs_node = fs_node;
    region->size = size;
    region->file_offset = file_offset;

    spinlock_init(&region->page_tree_lock);
    ptree_init(&region->page_tree);

    spin_lock(&mmap->lock);

    // This will find us a valid offset
    res = __mmap_locked_hint_offset(
            mmap,
            region,
            *hint_offset,
            size);
    if(res) {
        goto err3;
    }

    *hint_offset = region->tree_node.key;

    res = ptree_insert(
            &mmap->region_tree,
            &region->tree_node,
            region->tree_node.key);
    if(res) {
        eprintk("__mmap_locked_hint_offset returned an offset=%p which could not be inserted! (err=%s)\n",
                *hint_offset, errnostr(res));
        goto err3;
    }

    dprintk("mmap_map_region_exact mapped region [%p-%p)\n",
            region->tree_node.key,
            region->tree_node.key + region->size);

    spin_unlock(&mmap->lock);
    return 0;

err3:
    spin_unlock(&mmap->lock);
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
mmap_map_region_exact(
        struct process *process,
        fd_t file,
        uintptr_t file_offset,
        uintptr_t mmap_offset,
        size_t size,
        unsigned long mmap_flags)
{
    int res;

    // syscall_mmap should check these assumptions for user requests,
    // but the kernel might be invoking this function incorrectly
    DEBUG_ASSERT(ptr_orderof(mmap_offset) >= VMEM_MIN_PAGE_ORDER);
    DEBUG_ASSERT(ptr_orderof(size) >= VMEM_MIN_PAGE_ORDER);

    struct fs_node *fs_node;

    unsigned long mmap_type = mmap_flags & 0b11;

    if(mmap_type != MMAP_ANON) {
        struct file *desc =
            file_table_get_file(process->file_table, process, file);

        res = mmap_file_prot_check(desc, mmap_flags);
        if(res) {
            file_table_put_file(process->file_table, process, desc);
            goto err0;
        }

        fs_node = fs_path_get_fs_node(desc->path);
        if(fs_node == NULL) {
            file_table_put_file(process->file_table, process, desc);
            res = -EINVAL;
            goto err0;
        }

        res = fs_node_get(fs_node);
        if(res) {
            file_table_put_file(process->file_table, process, desc);
            goto err0;
        }

        file_table_put_file(process->file_table, process, desc);
    }
    else {
        // This is an anonymous mapping
        fs_node = NULL;
    }


    struct mmap *mmap = process->mmap;
    DEBUG_ASSERT(KERNEL_ADDR(mmap));

    struct mmap_region *region;
    region = kzmalloc(sizeof(struct mmap_region), KM_KERNEL);
    if(region == NULL) {
        res = -ENOMEM;
        goto err1;
    }

    region->mmap = mmap;
    region->mmap_flags = mmap_flags;
    region->fs_node = fs_node;
    region->size = size;
    region->file_offset = file_offset;
    region->tree_node.key = mmap_offset;

    spinlock_init(&region->page_tree_lock);
    dprintk("mmap_region page_tree_init region=%p [%p-%p)\n",
            region,
            region->tree_node.key,
            region->tree_node.key + region->size);
    ptree_init(&region->page_tree);

    uintptr_t end_offset = mmap_offset + size;

    spin_lock(&mmap->lock);

    // We need to check that this mapping doesn't conflict
    struct ptree_node *before =
        ptree_get_max_less(&mmap->region_tree, end_offset);
    if(before != NULL) {
        struct mmap_region *before_region =
            container_of(before, struct mmap_region, tree_node);
        uintptr_t before_ending = before->key + before_region->size;
        if(before_ending > mmap_offset) {
            eprintk("PID(%ld) mmap request [%p-%p) overlaps mapping [%p-%p)\n",
                   (sl_t)process->id,
                   mmap_offset,
                   end_offset,
                   before->key,
                   before_ending
                   );
            res = -EALREADY;
            goto err3;
        }
    }

    dprintk("mmap_map_region_exact mapped region [%p-%p)\n",
            region->tree_node.key,
            region->tree_node.key + region->size);

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
    if(fs_node) {
        fs_node_put(fs_node);
    }
err0:
    return res;
}

static int
mmap_unmap_region_lockless(
	struct mmap *mmap,
	struct mmap_region *region)
{
    int res;

    struct fs_node *fs_node = region->fs_node;

    dprintk("mmap_unmap_region: removing region [%p-%p)\n",
            region->tree_node.key, region->tree_node.key + region->size
            );

    struct ptree_node *removed = ptree_remove(&mmap->region_tree, region->tree_node.key);
    DEBUG_ASSERT(removed == &region->tree_node);

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
            eprintk("mmap_unmap_region: mmap_region_reclaim_page returned %s\n",
                    errnostr(res));
            return res;
        }

        struct ptree_node *next = ptree_get_first(&region->page_tree);
        if(next == page_node) {
            spin_unlock(&region->page_tree_lock);
            eprintk("mmap_unmap_region: Failed to reclaim mmap page\n");
            return -EINVAL;
        }
        page_node = next;
        num_reclaimed++;
    }

    dprintk("mmap_unmap_region: reclaimed %lld pages\n", (sll_t)num_reclaimed);
   
    if(fs_node) {
        fs_node_put(fs_node);
    }

    spin_unlock(&region->page_tree_lock);

    kfree(region);

    return 0;
}

int
mmap_unmap_region(
        struct process *process,
        uintptr_t mmap_offset)
{
    int res;

    struct mmap *mmap = process->mmap;
    DEBUG_ASSERT(KERNEL_ADDR(mmap));

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

    if(mmap_offset >= (region->tree_node.key + region->size)) {
        spin_unlock(&mmap->lock);
        return -ENXIO;
    }


    if(!((((uintptr_t)region->tree_node.key > (uintptr_t)process->user_ip)
      || ((uintptr_t)region->tree_node.key + region->size <= (uintptr_t)process->user_ip))))
    {
        return -EINVAL;
    }

    spin_lock(&mmap->lock);
    res = mmap_unmap_region_lockless(mmap, region);
    spin_unlock(&mmap->lock);
    return res;
}


int
mmap_region_load_page(
        struct mmap_region *region,
        uintptr_t page_offset,
        struct mmap_page **out)
{
    int res;

    struct fs_page *fs_page = NULL;
    void __phys * paddr = 0;
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

        DEBUG_ASSERT_MSG(
                KERNEL_ADDR(region->fs_node),
                "MMAP_SHARED or MMAP_PRIVATE region has NULL fs_node! region->mmap_flags=0x%lx, region_offset=%p",
                region->mmap_flags, region->tree_node.key);
        
        res = fs_node_page_order(region->fs_node, &order);
        if(res) {
            return res;
        }
        if(order < VMEM_MIN_PAGE_ORDER) {
            wprintk("Tried to mmap file with page order %ld, which is too small to mmap! (VMEM_MIN_PAGE_ORDER=%ld)\n",
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

        if(mmap_type == MMAP_PRIVATE) {
            page_flags |= MMAP_PAGE_COPY_ON_WRITE;
        }

        paddr = fs_page->paddr;

    } else {
        // This shouldn't be able to reach this function,
        // and should be caught during "mmap_map_region"
        panic("mmap_region_load_page with unknown mmap type! (not MMAP_ANON, MMAP_SHARED or MMAP_PRIVATE)\n");
    }

    struct mmap_page *page = kzmalloc(sizeof(struct mmap_page), KM_KERNEL);
    if(page == NULL) {
        if(page_flags & MMAP_PAGE_ANON) {
            page_free(order, paddr);
        }
        else {
            fs_node_put_page(region->fs_node, page->fs_page, 0);
        }
        return -ENOMEM;
    }

    page->order = order;
    page->flags = page_flags;
    page->phys_addr = paddr;
    if(page->flags & MMAP_ANON) {
        if(page->flags & MMAP_PAGE_COPY_ON_WRITE) {
            // This should never happen but stay consistent if our caller is weird
            page->anon_sharing_level = kmalloc(sizeof(atomic_t), KM_KERNEL);
            if(page->anon_sharing_level == NULL) {
                page_free(order, paddr);
                kfree(page);
                return -ENOMEM;
            }
            *page->anon_sharing_level = 1;
        } else {
            page->anon_sharing_level = NULL;
        }
    } else {
        page->fs_page = fs_page;
    }

    DEBUG_ASSERT(ptr_orderof(page->phys_addr) >= VMEM_MIN_PAGE_ORDER);

    dprintk("mmap_region page_tree insert: region=%p, page=%p, page->region_offset=%p, page->order=%ld\n",
            region, page, page->tree_node.key, page->order);
    res = ptree_insert(&region->page_tree, &page->tree_node, page_offset);
    if(res) {
        if(page_flags & MMAP_PAGE_ANON) {
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
    void __phys * new_page;

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

    // Clean-Up
    if((page->flags & MMAP_PAGE_ANON) == 0) {
        // File-Backed

        DEBUG_ASSERT(KERNEL_ADDR(region));
        DEBUG_ASSERT(KERNEL_ADDR(region->fs_node));

        struct fs_node *fs_node = region->fs_node;

        DEBUG_ASSERT(KERNEL_ADDR(page->fs_page));

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
        dprintk("Handling Anonymous Copy-On-Write Page Fault...\n");
        // Anonymous
        atomic_t *sharing_level = page->anon_sharing_level;
        DEBUG_ASSERT(KERNEL_ADDR(sharing_level));

        // Need this synchronization because
        atomic_t new_level = atomic_fetch_dec(sharing_level)-1;

        dprintk("Set Sharing Level to %d\n", new_level);

        if(new_level == 0) {
            // Free the old page (Really we should just use the old one TODO)
            dprintk("Freeing Page!\n");
            page_free(page->order, page->phys_addr);
            kfree(sharing_level);
        }
    }

    // Set up our page as if it is just a standard anonymous page
    page->flags &= ~MMAP_PAGE_COPY_ON_WRITE;
    page->flags |= MMAP_PAGE_ANON;
    page->phys_addr = new_page;
    page->anon_sharing_level = NULL;

    dprintk("populated page flags\n");

    // Remap the page into memory
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

    struct mmap *mmap = process->mmap;
    DEBUG_ASSERT(KERNEL_ADDR(mmap));

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

        uintptr_t region_offset = offset - region->tree_node.key;

        if((region->mmap_flags & MMAP_PROT_READ) == 0) {
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
        pnode = ptree_get_max_less_or_eq(&region->page_tree, region_offset);
        struct mmap_page *page =
            container_of(pnode, struct mmap_page, tree_node);
        if((pnode == NULL) ||
           (region_offset >= pnode->key + (1ULL<<page->order))) 
        {
            res = mmap_region_load_page(
                    region,
                    region_offset,
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

    struct mmap *mmap = process->mmap;
    DEBUG_ASSERT(KERNEL_ADDR(mmap));

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

        uintptr_t region_offset = offset - region->tree_node.key;

        if((region->mmap_flags & MMAP_PROT_WRITE) == 0) {
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
        pnode = ptree_get_max_less_or_eq(&region->page_tree, region_offset);
        struct mmap_page *page =
            container_of(pnode, struct mmap_page, tree_node);
        if((pnode == NULL) ||
           (region_offset >= pnode->key + (1ULL<<page->order))) 
        {
            res = mmap_region_load_page(
                    region,
                    region_offset,
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
            //printk("mmap_page_do_copy_on_write from process_write_usermem\n");
            res = mmap_page_do_copy_on_write(region, page);
            if(res) {
                spin_unlock(&region->page_tree_lock);
                spin_unlock_irq_restore(&mmap->lock, irq_flags);
                return res;
            }
        }

        if(page->flags & MMAP_PAGE_COPY_ON_WRITE) {
            spin_unlock(&region->page_tree_lock);
            spin_unlock_irq_restore(&mmap->lock, irq_flags);
            return -EINVAL;
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

    spin_unlock_irq_restore(&mmap->lock, irq_flags);
    return 0;
}

int
mmap_memset(
        struct process *process,
        uintptr_t offset,
        uint8_t value,
        size_t length)
{
    int res;

    // TODO: This is incredibly inefficient...

    while(length > 0) {
        res = mmap_write(
                process,
                offset,
                &value,
                1);
        if(res) {
            return res;
        }
        length--;
        offset++;
    }

    return 0;
}
int
mmap_user_strlen(
        struct process * process,
        uintptr_t offset,
        size_t max_strlen,
        size_t *out_len)
{
    int res;

    struct mmap *mmap = process->mmap;
    DEBUG_ASSERT(KERNEL_ADDR(mmap));
    DEBUG_ASSERT(ptr_orderof(mmap) >= orderof(typeof(*mmap)));
    DEBUG_ASSERT(KERNEL_ADDR(mmap->vmem_region));
    DEBUG_ASSERT(ptr_orderof(mmap->vmem_region) >= orderof(typeof(*mmap->vmem_region)));
    DEBUG_ASSERT(mmap->vmem_region->type == VMEM_REGION_TYPE_PAGED);
    DEBUG_ASSERT(mmap->vmem_region->size != 0);
    DEBUG_ASSERT(mmap->vmem_region->num_refs > 0);

    dprintk("mmap_user_strlen: PID(%ld), mmap=%p, offset=0x%lx, max=0x%lx\n",
            (sl_t)process->id, mmap, offset, max_strlen);

    int irq_flags = spin_lock_irq_save(&mmap->lock);

    size_t len = 0;

    int done = 0;
    while(!done && len < max_strlen) {

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

        DEBUG_ASSERT(ptr_orderof(region->tree_node.key) >= VMEM_MIN_PAGE_ORDER);
        DEBUG_ASSERT(ptr_orderof(region->tree_node.key) <= 64);
        DEBUG_ASSERT(region->size > 0);

        dprintk("region=%p [%p-%p)\n", region, region->tree_node.key, region->tree_node.key + region->size);

        spin_lock(&region->page_tree_lock);

        size_t region_offset = offset - region->tree_node.key;

        if((region->mmap_flags & MMAP_PROT_READ) == 0) {
            // The process is not allowed to read this page
            spin_unlock(&region->page_tree_lock);
            spin_unlock_irq_restore(&mmap->lock, irq_flags);
            return -EINVAL;
        }

        // Get or load the page
        pnode = ptree_get_max_less_or_eq(&region->page_tree, region_offset);
        struct mmap_page *page =
            container_of(pnode, struct mmap_page, tree_node);
        if((pnode == NULL) ||
           (region_offset >= (pnode->key + (1ULL<<page->order)))) 
        {
            dprintk("loading page (offset=%p)\n", region_offset);
            res = mmap_region_load_page(
                    region,
                    region_offset,
                    &page);
            if(res) {
                spin_unlock(&region->page_tree_lock);
                spin_unlock_irq_restore(&mmap->lock, irq_flags);
                return res;
            }
        } else {
            dprintk("already had page (offset=%p)\n", region_offset);
        }

        struct ptree_node *iter = ptree_get_first(&region->page_tree);
        for(; iter != NULL; iter = ptree_get_next(iter)) {
            struct mmap_page *iter_page =
                container_of(iter, struct mmap_page, tree_node);
            dprintk("page=%p, phys_addr=%p, order=%ld, fs_page=%p\n",
                    iter_page,
                    iter_page->phys_addr,
                    (sl_t)iter_page->order,
                    iter_page->fs_page);
        }


        if(page == NULL) {
            spin_unlock(&region->page_tree_lock);
            spin_unlock_irq_restore(&mmap->lock, irq_flags);
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
    
    spin_unlock_irq_restore(&mmap->lock, irq_flags);

    *out_len = len;
    return 0;
}

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
        struct excp_state *state,
        struct vmem_region_ref *ref,
        uintptr_t offset,
        unsigned long pf_flags,
        void *priv_state)
{
    dprintk("mmap_page_fault_handler offset=%p, pf_flags={%s%s%s%s%s}\n",
            offset,
            pf_flags & PF_FLAG_READ ? "[READ]" : "",
            pf_flags & PF_FLAG_WRITE ? "[WRITE]" : "",
            pf_flags & PF_FLAG_EXEC ? "[EXEC]" : "",
            pf_flags & PF_FLAG_USERMODE ? "[USER]" : "",
            pf_flags & PF_FLAG_NOT_PRESENT ? "" : "[PRESENT]"
            );
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

    if((page->flags & MMAP_PAGE_COPY_ON_WRITE) && (pf_flags & PF_FLAG_WRITE))
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

// Cloning

// Should be called holding the region lock of "from"
static int
mmap_page_clone(
        struct mmap_region *from_region,
        struct mmap_page *from,
        struct mmap_region *to)
{
    int res;

    struct mmap_page *page = kzmalloc(sizeof(struct mmap_page), KM_KERNEL);
    if(page == NULL) {
        return -ENOMEM;
    }

    page->flags = from->flags;
    page->order = from->order;
    page->flags &= ~MMAP_PAGE_MAPPED;

    // Set phys_addr and fs_page/anon_sharing_level
    if(from->flags & MMAP_PAGE_ANON) {
        if(from->flags & MMAP_PAGE_COPY_ON_WRITE) {
            // This page is already being shared between mmap's as copy-on-write
            page->anon_sharing_level = from->anon_sharing_level;
            atomic_t old_sharing_level = atomic_fetch_inc(from->anon_sharing_level);
            if(old_sharing_level <= 0) {
                // We caught this page in the middle of freeing it?
                // (shouldn't be possible)
                kfree(page);
                return -EINVAL;
            }
            page->phys_addr = from->phys_addr;
        } else {
            // We need to make this a shared anonymous copy-on-write page
           
            page->flags |= MMAP_PAGE_COPY_ON_WRITE;
            page->anon_sharing_level = kzmalloc(sizeof(atomic_t), KM_KERNEL);
            if(page->anon_sharing_level == NULL) {
                kfree(page);
                return -ENOMEM;
            }
            *page->anon_sharing_level = 2;

            // I'm fairly confident this is safe: these is accesses are questionable though
            res = mmap_region_unmap_page(from_region, from);
            if(res) {
                kfree(page->anon_sharing_level);
                kfree(page);
                return res;
            } 
            from->flags |= MMAP_PAGE_COPY_ON_WRITE;
            from->anon_sharing_level = page->anon_sharing_level;

            page->phys_addr = from->phys_addr;
        }
    } else {
        struct fs_page *fs_page = from->fs_page;
        DEBUG_ASSERT(KERNEL_ADDR(fs_page));

        res = fs_page_get(from_region->fs_node, fs_page);
        if(res) {
            kfree(page);
            return res;
        }

        page->fs_page = fs_page;
        page->phys_addr = from->phys_addr;
    }

    res = ptree_insert(
            &to->page_tree,
            &page->tree_node,
            from->tree_node.key);
    if(res) {
        if(page->flags & MMAP_PAGE_ANON) {
            // Anonymous
            atomic_t *sharing_level = page->anon_sharing_level;
            DEBUG_ASSERT(KERNEL_ADDR(sharing_level));

            // Need this synchronization because
            atomic_t new_level = atomic_fetch_dec(sharing_level)-1;

            if(new_level == 0) {
                // Free the old page (Really we should just use the old one TODO)
                page_free(page->order, page->phys_addr);
                kfree(sharing_level);
            }
            kfree(page);
            return res;
        } else {
            fs_node_put_page(from_region->fs_node, page->fs_page, 0);
            kfree(page);
            return res;
        }
    }
    
    return 0;
}

// Should be called holding the mmap lock of "from"
static int
mmap_region_clone(
        struct mmap_region *from,
        struct mmap *to)
{
    int res;

    struct mmap_region *region = kzmalloc(sizeof(struct mmap_region), KM_KERNEL);
    if(region == NULL) {
        return -ENOMEM;
    }
    memset(region, 0, sizeof(struct mmap_region));

    region->mmap = to;

    int irq_flags = spin_lock_irq_save(&from->page_tree_lock);

    region->size = from->size;
    region->file_offset = from->file_offset;
    region->mmap_flags = from->mmap_flags;
    region->fs_node = from->fs_node;
    if(region->fs_node) {
        fs_node_get(region->fs_node);
    }
    spinlock_init(&region->page_tree_lock);
    ptree_init(&region->page_tree);

    size_t region_offset = from->tree_node.key;

    res = ptree_insert(&to->region_tree, &region->tree_node, region_offset);
    if(res) {
        spin_unlock_irq_restore(&from->page_tree_lock, irq_flags);
	if(region->fs_node) {
	    fs_node_put(region->fs_node);
	}
        kfree(region);
        return res;
    }

    struct ptree_node *pnode;
    for(pnode = ptree_get_first(&from->page_tree);
        pnode != NULL;
        pnode = ptree_get_next(pnode))
    {
        struct mmap_page *page = container_of(pnode, struct mmap_page, tree_node);
        res = mmap_page_clone(from, page, region);
        if(res) {
            eprintk("Failed to clone mmap page! err=%s\n",
                    errnostr(res));
            spin_unlock_irq_restore(&from->page_tree_lock, irq_flags);
            // Our region will still be in the mmap just incomplete
            // (It should be freed on mmap destruction)
            return res;
        }
    }

    spin_unlock_irq_restore(&from->page_tree_lock, irq_flags);
    return 0;
}

int
mmap_clone(
        struct mmap *from,
        struct process *onto)
{
    int res;

    //mmap_dump(do_printk, from);

    res = mmap_create(from->vmem_region->size, onto);
    if(res) {
        return res;
    }
    struct mmap *mmap = onto->mmap;

    // No one should be able to access "onto->mmap" yet but just to be extra safe...
    spin_lock(&mmap->lock);

    int irq_flags = spin_lock_irq_save(&from->lock);
    struct ptree_node *pnode;
    for(pnode = ptree_get_first(&from->region_tree);
        pnode != NULL;
        pnode = ptree_get_next(pnode))
    {
        struct mmap_region *region =
            container_of(pnode, struct mmap_region, tree_node);
        res = mmap_region_clone(region, mmap);
        if(res) {
            spin_unlock_irq_restore(&from->lock, irq_flags);
            spin_unlock(&mmap->lock);
            return res;
        }
    }

    ilist_node_t *proc_node;
    ilist_for_each(proc_node, &from->process_list) {
        struct process *process = container_of(proc_node, struct process, mmap_list_node);
        DEBUG_ASSERT(KERNEL_ADDR(process));
        struct vmem_map *map = process->thread.mem_map;
        res = vmem_flush_map(map);
        if(res) {
            wprintk("Failed to flush vmem map after cloning mmap! (err=%s) (PID=%ld)\n",
                    errnostr(res),
                    process->id);
        }
    }

    spin_unlock_irq_restore(&from->lock, irq_flags);
    spin_unlock(&mmap->lock);

    //mmap_dump(do_printk, from);
    //mmap_dump(do_printk, onto->mmap);
    //dump_threads(do_printk);

    return 0;
}

static int
dump_mmap_page(
        printk_f *printer,
        struct mmap_region *region,
        struct mmap_page *page)
{
    (*printer)("\t\tPage [%p-%p] -> %p %s%s%s\n",
            region->tree_node.key + page->tree_node.key,
            region->tree_node.key + page->tree_node.key + (1ULL<<page->order),
            page->phys_addr,
            page->flags & MMAP_PAGE_ANON ? "[ANON]" : "",
            page->flags & MMAP_PAGE_MAPPED ? "[MAPPED]" : "",
            page->flags & MMAP_PAGE_COPY_ON_WRITE ? "[COW]" : ""
            );
    return 0;
}

static int
dump_mmap_region(
        printk_f *printer,
        struct mmap_region *region)
{
    int res;

    spin_lock(&region->page_tree_lock);

    (*printer)("\tRegion [%p-%p] %s%s%s %s%s%s\n",
            (uintptr_t)region->tree_node.key,
            (uintptr_t)region->tree_node.key + region->size,
            region->mmap_flags & MMAP_PROT_READ ? "[READ]" : "",
            region->mmap_flags & MMAP_PROT_WRITE ? "[WRITE]" : "",
            region->mmap_flags & MMAP_PROT_EXEC ? "[EXEC]" : "",
            region->mmap_flags & MMAP_ANON ? "[ANON]" : "",
            region->mmap_flags & MMAP_SHARED ? "[SHARED]" : "",
            region->mmap_flags & MMAP_PRIVATE ? "[PRIVATE]" : ""
            );

    struct ptree_node *pnode;
    for(pnode = ptree_get_first(&region->page_tree);
        pnode != NULL;
        pnode = ptree_get_next(pnode))
    {
        struct mmap_page *page =
            container_of(pnode, struct mmap_page, tree_node);
        res = dump_mmap_page(printer, region, page);
        if(res) {
            spin_unlock(&region->page_tree_lock);
            return res;
        }
    }

    spin_unlock(&region->page_tree_lock);
    return 0;
}

int
mmap_dump(
        printk_f *printer,
        struct mmap *mmap)
{
    int res;
    int irq_flags = spin_lock_irq_save(&mmap->lock);

    (*printer)("MMAP\n");

    struct ptree_node *pnode;
    for(pnode = ptree_get_first(&mmap->region_tree);
        pnode != NULL;
        pnode = ptree_get_next(pnode))
    {
        struct mmap_region *region =
            container_of(pnode, struct mmap_region, tree_node);
        res = dump_mmap_region(printer, region);
        if(res) {
            spin_unlock_irq_restore(&mmap->lock, irq_flags);
            return res;
        }
    }

    spin_unlock_irq_restore(&mmap->lock, irq_flags);
    return 0;
}
