
#include <kanawha/assert.h>
#include <kanawha/fs/node.h>
#include <kanawha/irq.h>
#include <kanawha/kmalloc.h>
#include <kanawha/page_alloc.h>
#include <kanawha/printk.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/proc/mmap.h>
#include <kanawha/proc/process.h>
#include <kanawha/ptree.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/syscall.h>
#include <kanawha/types.h>
#include <kanawha/vmem.h>
#include <kanawha/panic.h>

static inline void
mmap_lock_init(struct mmap *mmap)
{
    irq_lock_init(&mmap->lock);
}
static inline void
mmap_lock_acquire(struct mmap *mmap)
{
    irq_lock_acquire(&mmap->lock);
}
static inline void
mmap_lock_release(struct mmap *mmap)
{
    irq_lock_release(&mmap->lock);
}

static inline void
mmap_region_page_tree_lock_init(struct mmap_region *region)
{
    irq_lock_init(&region->page_tree_lock);
}
static inline void
mmap_region_page_tree_lock_acquire(struct mmap_region *region)
{
    irq_lock_acquire(&region->page_tree_lock);
}
static inline void
mmap_region_page_tree_lock_release(struct mmap_region *region)
{
    irq_lock_release(&region->page_tree_lock);
}

static int
mmap_unmap_region_lockless(struct mmap *mmap, struct mmap_region *region);

int
mmap_create(size_t size, struct process *initial_process)
{
    int res;

    struct mmap *mmap = kzmalloc(sizeof(struct mmap), KM_KERNEL);
    if(mmap == NULL)
    {
        return -ENOMEM;
    }

    mmap_lock_init(mmap);
    ptree_init(&mmap->region_tree);
    ilist_init(&mmap->process_list);

    mmap->vmem_region =
        vmem_region_create_paged(size, mmap_page_fault_handler, mmap);

    if(mmap->vmem_region == NULL)
    {
        kfree(mmap);
        return -EINVAL;
    }

    res = mmap_attach(mmap, initial_process);
    if(res)
    {
        vmem_region_destroy(mmap->vmem_region);
        kfree(mmap);
        return res;
    }

    return 0;
}

int
mmap_attach(struct mmap *mmap, struct process *process)
{
    int res;

    mmap_lock_acquire(mmap);

    process->mmap = mmap;
    ilist_push_tail(&mmap->process_list, &process->mmap_list_node);

    res = vmem_map_map_region(process->thread.mem_map, mmap->vmem_region, 0x0);
    if(res)
    {
        ilist_remove(&mmap->process_list, &process->mmap_list_node);
        process->mmap = NULL;
        mmap_lock_release(mmap);
        return res;
    }

    process->mmap_ref = vmem_map_get_region(process->thread.mem_map, 0x0);
    DEBUG_ASSERT(KERNEL_ADDR(process->mmap_ref));

    mmap_lock_release(mmap);
    dprintk("Attached MMAP %p to Process %p\n", mmap, process);
    return 0;
}

int
mmap_deattach(struct mmap *mmap, struct process *process)
{
    int res;

    mmap_lock_acquire(mmap);

    res = vmem_map_unmap_region(process->thread.mem_map, process->mmap_ref);
    if(res)
    {
        mmap_lock_release(mmap);
        return res;
    }

    ilist_remove(&mmap->process_list, &process->mmap_list_node);
    process->mmap = NULL;

    if(ilist_empty(&mmap->process_list))
    {

        dprintk("Destroying MMAP\n");

        while(1)
        {
            struct ptree_node *region_node =
                ptree_get_first(&mmap->region_tree);
            if(region_node == NULL)
            {
                break;
            }
            res = mmap_unmap_region_lockless(
                mmap,
                container_of(region_node, struct mmap_region, tree_node));
            if(res)
            {
                eprintk("Failed to unmap region on mmap "
                        "destruction! (err=%s)\n",
                        errnostr(res));
            }
        }

        // This was the last process to hold a reference to this mmap
        res = vmem_region_destroy(mmap->vmem_region);
        if(res)
        {
            wprintk("Failed to destroy mmap vmem_region! (err=%s)\n",
                    errnostr(res));
        }

        // We need to release the lock to restore IRQ state
        mmap_lock_release(mmap);
        kfree(mmap);
        return 0;
    }

    mmap_lock_release(mmap);
    return 0;
}

const char *
mmap_region_get_name(struct mmap_region *region)
{
    if(region->has_name)
    {
        return region->name;
    }
    else
    {
        return "";
    }
}

int
mmap_region_map_page(struct mmap_region *region, struct mmap_page *page)
{
    int res;

    if(page->flags & MMAP_PAGE_MAPPED)
    {
        dprintk("mmap_region_map_page: page is already mapped flags = %p\n",
                (uintptr_t)page->flags);
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
        if((page->flags & MMAP_PAGE_COPY_ON_WRITE) == 0)
        {
            vmem_flags |= VMEM_REGION_WRITE;
        }
        else
        {
            dprintk("Avoiding mapping mmap page as writable because it is "
                    "copy-on-write\n");
        }
    }

    if((region->mmap_flags & MMAP_PROT_EXEC))
    {
        vmem_flags |= VMEM_REGION_EXEC;
    }

    DEBUG_ASSERT(KERNEL_ADDR(region));
    DEBUG_ASSERT(KERNEL_ADDR(region->mmap));
    DEBUG_ASSERT(KERNEL_ADDR(region->mmap->vmem_region));
    res = vmem_paged_region_map(region->mmap->vmem_region,
                                region->tree_node.key + page->tree_node.key,
                                mpage_get_phys(page->backing_page),
                                mpage_get_size(page->backing_page),
                                vmem_flags);
    if(res)
    {
        eprintk("mmap_region_map_page: vmem_paged_region_map returned %s, "
                "region_offset=%p, region_base=%p, offset=%p\n",
                errnostr(res),
                page->tree_node.key,
                region->tree_node.key,
                page->tree_node.key + region->tree_node.key);
        return res;
    }

    page->flags |= MMAP_PAGE_MAPPED;
    dprintk("mmap_region_map_page: mapped page region-offset=[%p-%p)\n",
            page->tree_node.key,
            page->tree_node.key + mpage_get_size(page->backing_page));

    return 0;
}

static inline int
mmap_region_unmap_page(struct mmap_region *region, struct mmap_page *page)
{
    int res;

    if((page->flags & MMAP_PAGE_MAPPED) == 0)
    {
        return 0;
    }

    res = vmem_paged_region_unmap(region->mmap->vmem_region,
                                  region->tree_node.key + page->tree_node.key,
                                  mpage_get_size(page->backing_page));
    if(res)
    {
        return res;
    }

    page->flags &= ~MMAP_PAGE_MAPPED;

    return 0;
}

// Unmap, and unload the page
static int
mmap_region_reclaim_page(struct mmap_region *region, struct mmap_page *page)
{
    int res;

    res = mmap_region_unmap_page(region, page);
    if(res)
    {
        return res;
    }

    int modified;

    // Assume the worst (TODO: actually enable checking page table "dirty" bit)
    if((region->mmap_flags & MMAP_PROT_WRITE))
    {
        modified = 1;
    }
    else
    {
        modified = 0;
    }

    DEBUG_ASSERT(KERNEL_ADDR(page->backing_page));
    if(modified) {
        mpage_mark(page->backing_page, MPAGE_MARK_DIRTY);
    }
    res = mpage_put(page->backing_page);
    if(res)
    {
        return res;
    }

    // Our backing memory should be free now

    struct ptree_node *rem =
        ptree_remove(&region->page_tree, page->tree_node.key);
    DEBUG_ASSERT(rem == &page->tree_node);

    kfree(page);

    return 0;
}

static int
mmap_file_prot_check(struct file *desc, unsigned long mmap_flags)
{
    DEBUG_ASSERT(KERNEL_ADDR(desc));

    unsigned long mmap_type = (mmap_flags & MMAP_FLAGS_TYPE_MASK);

    unsigned long aflags = fs_file_get_access_flags(desc);

    if((mmap_flags & MMAP_PROT_READ) &&
       (aflags & FILE_PERM_READ) == 0)
    {
        eprintk("mmap_file_prot_check: read permission fail!\n");
        return -EPERM;
    }
    if((mmap_flags & MMAP_PROT_WRITE) &&
       (aflags & FILE_PERM_WRITE) == 0)
    {
        if((mmap_type == MMAP_PRIVATE) && (aflags & FILE_PERM_READ))
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
        }
        else
        {
            eprintk("mmap_file_prot_check: write permission fail!\n");
            return -EPERM;
        }
    }
    if((mmap_flags & MMAP_PROT_EXEC) &&
       (aflags & FILE_PERM_EXEC) == 0)
    {
        eprintk("mmap_file_prot_check: exec permission fail!\n");
        return -EPERM;
    }

    return 0;
}

// Needs the mmap->lock to be held,
// and set's region->tree_node.key to a valid mmap_offset
static int
__mmap_locked_hint_offset(struct process *process,
                          struct mmap *mmap,
                          uintptr_t *hint_offset,
                          size_t size)
{
    // TODO: Actually take the hint into account

    size_t mmap_size = mmap->vmem_region->size;

    if(size >= mmap_size)
    {
        wprintk("process(%ld)[\"%s\"] MMAP requested too large of a region! "
                "(requested=0x%lx, mmap_size=0x%lx)\n",
                (sl_t)process->id,
#ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
                (process->tracked_exec ? process->tracked_exec : ""),
#else
                "",
#endif /* CONFIG_DEBUG_TRACK_PROCESS_EXEC */
                (ul_t)size,
                (ul_t)mmap_size);
        return -ENOMEM;
    }

    struct ptree_node *before_node;
    before_node = ptree_get_first(&mmap->region_tree);

    // If there are no regions at all, we will map at "midway"
    // (Roughly in the middle of user-memory)
    uintptr_t midway = mmap->vmem_region->size / 2;
    midway &= ~((1ULL << VMEM_MIN_PAGE_ORDER) - 1);
    uintptr_t cur_offset = midway;

    while(before_node)
    {
        struct mmap_region *before_region =
            container_of(before_node, struct mmap_region, tree_node);

        cur_offset = before_node->key + before_region->size;

        if((mmap_size - size) < cur_offset)
        {
            // Would run off the end of user memory
            wprintk("Process MMAP ran out of virtual memory! (mmap_size=0x%lx, "
                    "size=0x%lx, cur_offset=0x%lx)\n",
                    (ul_t)mmap_size,
                    (ul_t)size,
                    (ul_t)cur_offset);
            return -ENOMEM;
        }

        uintptr_t cur_end = cur_offset + size;

        struct ptree_node *after_node = ptree_get_next(before_node);
        if(after_node == NULL)
        {
            break;
        }

        if(cur_end > after_node->key)
        {
            // Not enough room between the regions
            before_node = after_node;
            continue;
        }

        // We can fit between the two regions
        *hint_offset = cur_offset;
        return 0;
    }

    // We reached the end, there is no region after "cur_offset"
    if((mmap_size - size) < cur_offset)
    {
        // Not enough room before the end of user-memory
        return -ENOMEM;
    }

    *hint_offset = cur_offset;
    return 0;
}

int
mmap_map_region(struct process *process,
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
    char *name_clone = NULL;

    if(mmap_type != MMAP_ANON)
    {
        struct file *desc =
            file_table_get_file(process->file_table, process, file);
        if(desc == NULL)
        {
            res = -EINVAL;
            goto err0;
        }

        res = mmap_file_prot_check(desc, mmap_flags);
        if(res)
        {
            fs_file_put(desc);
            goto err0;
        }

        fs_node = fs_file_get_node(desc);
        if(fs_node == NULL)
        {
            fs_file_put(desc);
            res = -EINVAL;
            goto err0;
        }

        {
            name_clone = NULL;
            struct fs_path *path = fs_file_get_path(desc);
            if(path != NULL) {
                name_clone = kstrdup(fs_path_get_name(path), KM_KERNEL);
                fs_path_put(path);
            }

            // name_clone may be NULL still
        }

        fs_file_put(desc);
    }
    else
    {
        // This is an anonymous mapping
        fs_node = NULL;
    }

    struct mmap *mmap = process->mmap;
    DEBUG_ASSERT(KERNEL_ADDR(mmap));

    struct mmap_region *region;
    region = kzmalloc(sizeof(struct mmap_region), KM_KERNEL);
    if(region == NULL)
    {
        res = -ENOMEM;
        goto err1;
    }

    if(name_clone == NULL)
    {
        region->has_name = 0;
        region->name = "";
    }
    else
    {
        region->has_name = 1;
        region->name = name_clone;
    }
    region->mmap = mmap;
    region->mmap_flags = mmap_flags;
    region->fs_node = fs_node;
    region->size = size;
    region->file_offset = file_offset;

    mmap_region_page_tree_lock_init(region);
    ptree_init(&region->page_tree);

    mmap_lock_acquire(mmap);

    // This will find us a valid offset
    res = __mmap_locked_hint_offset(process, mmap, hint_offset, size);
    if(res)
    {
        goto err3;
    }

    region->tree_node.key = *hint_offset;

    res = ptree_insert(&mmap->region_tree,
                       &region->tree_node,
                       region->tree_node.key);
    if(res)
    {
        eprintk("__mmap_locked_hint_offset returned an offset=%p which could "
                "not be inserted! (err=%s)\n",
                *hint_offset,
                errnostr(res));
        goto err3;
    }

    dprintk("mmap_map_region_exact mapped region [%p-%p)\n",
            region->tree_node.key,
            region->tree_node.key + region->size);

    mmap_lock_release(mmap);
    return 0;

err3:
    mmap_lock_release(mmap);
    // err2:
    if(region->has_name)
    {
        kfree(region->name);
    }
    kfree(region);
err1:
    if(fs_node)
    {
        fs_node_put(fs_node);
    }
err0:
    return res;
}

int
mmap_map_region_exact(struct process *process,
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

    if(mmap_type != MMAP_ANON)
    {
        struct file *desc =
            file_table_get_file(process->file_table, process, file);

        res = mmap_file_prot_check(desc, mmap_flags);
        if(res)
        {
            fs_file_put(desc);
            goto err0;
        }

        fs_node = fs_file_get_node(desc);
        if(fs_node == NULL)
        {
            fs_file_put(desc);
            res = -EINVAL;
            goto err0;
        }

        fs_file_put(desc);
    }
    else
    {
        // This is an anonymous mapping
        fs_node = NULL;
    }

    struct mmap *mmap = process->mmap;
    DEBUG_ASSERT(KERNEL_ADDR(mmap));

    struct mmap_region *region;
    region = kzmalloc(sizeof(struct mmap_region), KM_KERNEL);
    if(region == NULL)
    {
        res = -ENOMEM;
        goto err1;
    }

    region->mmap = mmap;
    region->mmap_flags = mmap_flags;
    region->fs_node = fs_node;
    region->size = size;
    region->file_offset = file_offset;
    region->tree_node.key = mmap_offset;

    mmap_region_page_tree_lock_init(region);
    dprintk("mmap_region page_tree_init region=%p [%p-%p)\n",
            region,
            region->tree_node.key,
            region->tree_node.key + region->size);
    ptree_init(&region->page_tree);

    uintptr_t end_offset = mmap_offset + size;

    mmap_lock_acquire(mmap);

    // We need to check that this mapping doesn't conflict
    struct ptree_node *before =
        ptree_get_max_less(&mmap->region_tree, end_offset);
    if(before != NULL)
    {
        struct mmap_region *before_region =
            container_of(before, struct mmap_region, tree_node);
        uintptr_t before_ending = before->key + before_region->size;
        if(before_ending > mmap_offset)
        {
            eprintk("PID(%ld) mmap request [%p-%p) overlaps mapping "
                    "[%p-%p)\n",
                    (sl_t)process->id,
                    mmap_offset,
                    end_offset,
                    before->key,
                    before_ending);
            res = -EALREADY;
            goto err3;
        }
    }

    dprintk("mmap_map_region_exact mapped region [%p-%p)\n",
            region->tree_node.key,
            region->tree_node.key + region->size);

    res = ptree_insert(&mmap->region_tree, &region->tree_node, mmap_offset);
    if(res)
    {
        goto err3;
    }

    mmap_lock_release(mmap);
    return 0;

err3:
    mmap_lock_release(mmap);
    // err2:
    kfree(region);
err1:
    if(fs_node)
    {
        fs_node_put(fs_node);
    }
err0:
    return res;
}

int
mmap_find_free_region(struct process *process,
                      uintptr_t *hint_offset,
                      size_t size)
{
    int res;

    // syscall_mmap should check these assumptions for user requests,
    // but the kernel might be invoking this function incorrectly
    DEBUG_ASSERT(size > 0);
    DEBUG_ASSERT(ptr_orderof(size) >= VMEM_MIN_PAGE_ORDER);

    struct fs_node *fs_node;

    struct mmap *mmap = process->mmap;
    DEBUG_ASSERT(KERNEL_ADDR(mmap));

    mmap_lock_acquire(mmap);

    // This will find us a valid offset
    res = __mmap_locked_hint_offset(process, mmap, hint_offset, size);
    if(res)
    {
        goto err;
    }

    mmap_lock_release(mmap);
    return 0;

err:
    mmap_lock_release(mmap);
    return res;
}
static int
mmap_unmap_region_lockless(struct mmap *mmap, struct mmap_region *region)
{
    int res;

    struct fs_node *fs_node = region->fs_node;

    dprintk("mmap_unmap_region: removing region [%p-%p)\n",
            region->tree_node.key,
            region->tree_node.key + region->size);

    struct ptree_node *removed =
        ptree_remove(&mmap->region_tree, region->tree_node.key);
    DEBUG_ASSERT(removed == &region->tree_node);

    mmap_region_page_tree_lock_acquire(region);

    __maybe_unused size_t num_reclaimed = 0;

    struct ptree_node *page_node = ptree_get_first(&region->page_tree);
    while(page_node != NULL)
    {
        struct mmap_page *page =
            container_of(page_node, struct mmap_page, tree_node);

        res = mmap_region_reclaim_page(region, page);
        if(res)
        {
            mmap_region_page_tree_lock_release(region);
            eprintk("mmap_unmap_region: mmap_region_reclaim_page "
                    "returned %s\n",
                    errnostr(res));
            return res;
        }

        struct ptree_node *next = ptree_get_first(&region->page_tree);
        if(next == page_node)
        {
            mmap_region_page_tree_lock_release(region);
            eprintk("mmap_unmap_region: Failed to reclaim mmap page\n");
            return -EINVAL;
        }
        page_node = next;
        num_reclaimed++;
    }

    dprintk("mmap_unmap_region: reclaimed %lld pages\n", (sll_t)num_reclaimed);

    if(fs_node)
    {
        fs_node_put(fs_node);
    }

    if(region->has_name)
    {
        kfree(region->name);
    }

    mmap_region_page_tree_lock_release(region);

    kfree(region);

    return 0;
}

int
mmap_unmap_region(struct process *process, uintptr_t mmap_offset)
{
    int res;

    struct mmap *mmap = process->mmap;
    DEBUG_ASSERT(KERNEL_ADDR(mmap));

    mmap_lock_acquire(mmap);

    struct ptree_node *pnode =
        ptree_get_max_less_or_eq(&mmap->region_tree, mmap_offset);
    if(pnode == NULL)
    {
        mmap_lock_release(mmap);
        return -ENXIO;
    }

    struct mmap_region *region =
        container_of(pnode, struct mmap_region, tree_node);

    if(mmap_offset >= (region->tree_node.key + region->size))
    {
        mmap_lock_release(mmap);
        return -ENXIO;
    }

    if(!((((uintptr_t)region->tree_node.key > (uintptr_t)process->user_ip) ||
          ((uintptr_t)region->tree_node.key + region->size <=
           (uintptr_t)process->user_ip))))
    {
        mmap_lock_release(mmap);
        return -EINVAL;
    }

    res = mmap_unmap_region_lockless(mmap, region);
    mmap_lock_release(mmap);
    return res;
}

int
mmap_region_load_page(struct mmap_region *region,
                      uintptr_t page_offset,
                      struct mmap_page **out)
{
    int res;

    struct mpage *backing_page = NULL;
    unsigned long page_flags = 0;

    unsigned long mmap_type = region->mmap_flags & 0b11;

    if(mmap_type == MMAP_ANONYMOUS)
    {
        order_t order = VMEM_MIN_PAGE_ORDER;
        backing_page = mpage_get_anonymous(order);
        if(backing_page == NULL) {
            return -ENOMEM;
        }

        // Clear the page
        void *page_data = (void *)__va(mpage_get_phys(backing_page));
        memset(page_data, 0, mpage_get_size(backing_page));

        // Align our page offset to the base of the page
        page_offset &= ~((1ULL << order) - 1);

        page_flags |= MMAP_PAGE_ANON;
    }
    else if(mmap_type == MMAP_SHARED || mmap_type == MMAP_PRIVATE)
    {

        DEBUG_ASSERT_MSG(KERNEL_ADDR(region->fs_node),
                         "MMAP_SHARED or MMAP_PRIVATE region has NULL fs_node! "
                         "region->mmap_flags=0x%lx, region_offset=%p",
                         region->mmap_flags,
                         region->tree_node.key);

        order_t order;
        res = fs_node_page_order(region->fs_node, &order);
        if(res)
        {
            return res;
        }
        if(order < VMEM_MIN_PAGE_ORDER)
        {
            wprintk("Tried to mmap file with page order %ld, which is too "
                    "small to mmap! (VMEM_MIN_PAGE_ORDER=%ld)\n",
                    (sl_t)order,
                    (sl_t)VMEM_MIN_PAGE_ORDER);
            return -EINVAL;
        }

        uintptr_t pfn = page_offset >> order;

        // Patch our page offset
        page_offset = pfn << order;

        // Add our region file offset
        if(ptr_orderof(region->file_offset) < order)
        {
            eprintk("region->file_offset is not aligned to the file "
                    "page size! "
                    "(file_offset=%p, page_order=%ld\n",
                    region->file_offset,
                    (sl_t)order);
            return -EINVAL;
        }

        pfn += (region->file_offset >> order);

        {
            struct fs_page *fs_page =
                fs_node_get_fs_page(region->fs_node, pfn, FS_NODE_GET_PAGE_MAY_CREATE);
            if(fs_page == NULL)
            {
                return -EINVAL;
            }

            backing_page = fs_page_get_as_mpage(fs_page);
            fs_page_put(fs_page);
            if(backing_page == NULL) {
                return -EINVAL;
            }
        }

        if(mmap_type == MMAP_PRIVATE)
        {
            page_flags |= MMAP_PAGE_COPY_ON_WRITE;
        }
    }
    else
    {
        // This shouldn't be able to reach this function,
        // and should be caught during "mmap_map_region"
        panic("mmap_region_load_page with unknown mmap type! (not "
              "MMAP_ANON, "
              "MMAP_SHARED or MMAP_PRIVATE)\n");
    }

    struct mmap_page *page = kzmalloc(sizeof(struct mmap_page), KM_KERNEL);
    if(page == NULL)
    {
        mpage_put(page->backing_page);
        return -ENOMEM;
    }

    page->flags = page_flags;
    DEBUG_ASSERT(KERNEL_ADDR(backing_page));
    page->backing_page = backing_page;

    DEBUG_ASSERT(ptr_orderof(mpage_get_phys(page->backing_page)) >= VMEM_MIN_PAGE_ORDER);

    dprintk("mmap_region page_tree insert: region=%p, page=%p, "
            "page->region_offset=%p, order=%ld\n",
            region,
            page,
            page->tree_node.key,
            mpage_get_order(page->backing_page));
    res = ptree_insert(&region->page_tree, &page->tree_node, page_offset);
    if(res)
    {
        mpage_put(page->backing_page);
        kfree(page);
        return res;
    }

    *out = page;

    return 0;
}

int
mmap_page_do_copy_on_write(struct mmap_region *region, struct mmap_page *page)
{
    int res;

    dprintk("PID(%P) mmap_page_do_copy_on_write(region=%p, page=%p, page->offset=%p)\n",
            region,
            page,
            page->tree_node.key);

    res = mmap_region_unmap_page(region, page);
    if(res)
    {
        eprintk("mmap_page_do_copy_on_write: mmap_region_unmap_page "
                "returned (%s)\n",
                errnostr(res));
        return res;
    }
    dprintk("unmapped page\n");

    DEBUG_ASSERT(KERNEL_ADDR(page->backing_page));

    // The process tried to write to a "copy-on-write" page,
    // allocate a new anonymous page for the copy.
    struct mpage *new_backing_page = mpage_get_anonymous(mpage_get_order(page->backing_page));
    if(new_backing_page == NULL)
    {
        eprintk("mmap_page_do_copy_on_write: page_alloc returned %s\n",
                errnostr(res));
        mmap_region_map_page(region, page);
        return res;
    }

    // Copy the data over
    void *new_data = (void *)__va(mpage_get_phys(new_backing_page));
    void *old_data = (void *)__va(mpage_get_phys(page->backing_page));
    memcpy(new_data, old_data, mpage_get_size(page->backing_page));

    DEBUG_ASSERT(KERNEL_ADDR(region));

    res = mpage_put(page->backing_page);
    if(res)
    {
        mmap_region_map_page(region, page);
        mpage_put(new_backing_page);
        eprintk("mmap_page_do_copy_on_write: mpage_put "
                "returned %s\n",
                errnostr(res));
        return res;
    }
    dprintk("put page\n");

    // Set up our page as if it is just a standard anonymous page
    page->flags &= ~MMAP_PAGE_COPY_ON_WRITE;
    page->flags |= MMAP_PAGE_ANON;
    page->backing_page = new_backing_page;

    dprintk("populated page flags\n");

    // Remap the page into memory
    res = mmap_region_map_page(region, page);
    if(res)
    {
        // We can potentially survive this, it'll just become an unmapped
        // but loaded anonymous page, and we'll fault again and try to map
        // it, (if it fails then, then we should terminate the process)
        eprintk("mmap_page_do_copy_on_write: during remapping of "
                "copy-on-write "
                "page, mmap_region_map_page returned %s\n",
                errnostr(res));
    }

    dprintk("mmap_page_do_copy_on_write finished\n");
    return 0;
}

#define MMAP_DIRECT_ACCESS_WRITE (0)
#define MMAP_DIRECT_ACCESS_READ  (1)
int
mmap_direct_access(
        struct process *process,
        uintptr_t offset,
        void *data,
        size_t length,
        unsigned int mode)
{
    int res;

    struct mmap *mmap = process->mmap;
    DEBUG_ASSERT(KERNEL_ADDR(mmap));

    dprintk("mmap_direct_access(pid=%ld, offset=%p, data=%p, length=0x%llx)\n",
            (sl_t)process->id,
            offset,
            data,
            (ull_t)length);

    // Overflow checking
    if(~(uintptr_t)(0) - offset < length)
    {
        eprintk("mmap_direct_access(process=%ld,offset=0x%llx,len=0x%llx) Overflow "
                "detected!\n",
                (sl_t)process->id,
                (ull_t)offset,
                (ull_t)length);
        return -EINVAL;
    }

    mmap_lock_acquire(mmap);

    if(offset + length > mmap->vmem_region->size)
    {
        mmap_lock_release(mmap);
        return -EINVAL;
    }

    while(length > 0)
    {

        struct ptree_node *pnode;
        pnode = ptree_get_max_less_or_eq(&mmap->region_tree, offset);

        struct mmap_region *region =
            container_of(pnode, struct mmap_region, tree_node);

        if((pnode == NULL) || (offset >= region->size + pnode->key))
        {
            mmap_lock_release(mmap);
            return -EINVAL;
        }

        mmap_region_page_tree_lock_acquire(region);

        uintptr_t region_offset = offset - region->tree_node.key;

        if(mode == MMAP_DIRECT_ACCESS_READ && (region->mmap_flags & MMAP_PROT_READ) == 0)
        {
            // The process is not allowed to read this page
            eprintk("mmap_direct_access(process=%ld,offset=0x%llx,len=0x%llx,READ)"
                    " Page is not Mapped as Readable!\n",
                    (sl_t)process->id,
                    (ull_t)offset,
                    (ull_t)length);
            mmap_region_page_tree_lock_release(region);
            mmap_lock_release(mmap);
            return -EINVAL;
        }
        if(mode == MMAP_DIRECT_ACCESS_WRITE && (region->mmap_flags & MMAP_PROT_WRITE) == 0)
        {
            // The process is not allowed to write this page
            mmap_region_page_tree_lock_release(region);
            mmap_lock_release(mmap);
            eprintk("mmap_direct_access(process=%ld,offset=0x%llx,len=0x%llx,WRITE)"
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
           (region_offset >= pnode->key + mpage_get_size(page->backing_page)))
        {
            res = mmap_region_load_page(region, region_offset, &page);
            if(res)
            {
                mmap_region_page_tree_lock_release(region);
                mmap_lock_release(mmap);
                return res;
            }
        }

        if(page == NULL)
        {
            mmap_region_page_tree_lock_release(region);
            mmap_lock_release(mmap);
            return -EINVAL;
        }

        if(mode == MMAP_DIRECT_ACCESS_WRITE) {
            if(page->flags & MMAP_PAGE_COPY_ON_WRITE)
            {
                res = mmap_page_do_copy_on_write(region, page);
                if(res)
                {
                    mmap_region_page_tree_lock_release(region);
                    mmap_lock_release(mmap);
                    return res;
                }
            }
            if(page->flags & MMAP_PAGE_COPY_ON_WRITE)
            {
                mmap_region_page_tree_lock_release(region);
                mmap_lock_release(mmap);
                return -EINVAL;
            }
        }

        void __phys *page_paddr = mpage_get_phys(page->backing_page);
        void *page_data = (void *)__va(page_paddr);

        uintptr_t page_offset = page->tree_node.key;
        size_t page_size = mpage_get_size(page->backing_page);
        size_t page_relative_offset = region_offset - page_offset;
        size_t room_avail = page_size - page_relative_offset;

        if(mode == MMAP_DIRECT_ACCESS_READ) {
            if(length <= room_avail)
            {
                memcpy(data, page_data + page_relative_offset, length);
                length = 0;
            }
            else
            {
                memcpy(data, page_data + page_relative_offset, room_avail);
                length -= room_avail;
                data += room_avail;
                offset += room_avail;
            }
        }
        else if(mode == MMAP_DIRECT_ACCESS_WRITE) {
            if(length <= room_avail)
            {
                //printk("mmap_write: memcpy (length=0x%lx)\n", length);
                memcpy(page_data + page_relative_offset, data, length);
                length = 0;
            }
            else
            {
                //printk("mmap_write: memcpy (length=0x%lx)\n", room_avail);
                memcpy(page_data + page_relative_offset, data, room_avail);
                length -= room_avail;
                data += room_avail;
                offset += room_avail;
            }
        }

        mmap_region_page_tree_lock_release(region);
    }

    mmap_lock_release(mmap);
    return 0;
}

int
mmap_read(struct process *process, uintptr_t offset, void *dst, size_t length)
{
    return mmap_direct_access(process, offset, dst, length, MMAP_DIRECT_ACCESS_READ);
}

int
mmap_write(struct process *process, uintptr_t offset, void *src, size_t length)
{
    return mmap_direct_access(process, offset, src, length, MMAP_DIRECT_ACCESS_WRITE);
}

int
mmap_memset(struct process *process,
            uintptr_t offset,
            uint8_t value,
            size_t length)
{
    int res;

    struct mmap *mmap = process->mmap;
    DEBUG_ASSERT(KERNEL_ADDR(mmap));

    // Overflow checking
    if(~(uintptr_t)(0) - offset < length)
    {
        return -EINVAL;
    }

    mmap_lock_acquire(mmap);

    if(offset + length > mmap->vmem_region->size)
    {
        mmap_lock_release(mmap);
        return -EINVAL;
    }

    while(length > 0)
    {

        struct ptree_node *pnode;
        pnode = ptree_get_max_less_or_eq(&mmap->region_tree, offset);

        struct mmap_region *region =
            container_of(pnode, struct mmap_region, tree_node);

        if((pnode == NULL) || (offset >= region->size + pnode->key))
        {
            mmap_lock_release(mmap);
            return -EINVAL;
        }

        uintptr_t region_offset = offset - region->tree_node.key;

        if((region->mmap_flags & MMAP_PROT_WRITE) == 0)
        {
            // The process is not allowed to write this page
            mmap_region_page_tree_lock_release(region);
            mmap_lock_release(mmap);
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
           (region_offset >= pnode->key + mpage_get_size(page->backing_page)))
        {
            res = mmap_region_load_page(region, region_offset, &page);
            if(res)
            {
                mmap_region_page_tree_lock_release(region);
                mmap_lock_release(mmap);
                return res;
            }
        }

        if(page == NULL)
        {
            mmap_region_page_tree_lock_release(region);
            mmap_lock_release(mmap);
            return -EINVAL;
        }

        if(page->flags & MMAP_PAGE_COPY_ON_WRITE)
        {
            res = mmap_page_do_copy_on_write(region, page);
            if(res)
            {
                mmap_region_page_tree_lock_release(region);
                mmap_lock_release(mmap);
                return res;
            }
        }

        if(page->flags & MMAP_PAGE_COPY_ON_WRITE)
        {
            mmap_region_page_tree_lock_release(region);
            mmap_lock_release(mmap);
            return -EINVAL;
        }

        void __phys *page_paddr = mpage_get_phys(page->backing_page);
        void *page_data = (void *)__va(page_paddr);

        uintptr_t page_offset = page->tree_node.key;
        size_t page_size = mpage_get_size(page->backing_page);
        size_t page_relative_offset = region_offset - page_offset;
        size_t room_avail = page_size - page_relative_offset;

        if(length <= room_avail)
        {
            //printk("mmap_memset: memset (length=0x%lx)\n", length);
            memset(page_data + page_relative_offset, value, length);
            length = 0;
        }
        else
        {
            // printk("mmap_memset: memset (length=0x%lx)\n", room_avail);
            memset(page_data + page_relative_offset, value, room_avail);
            length -= room_avail;
            offset += room_avail;
        }

        mmap_region_page_tree_lock_release(region);
    }

    mmap_lock_release(mmap);
    return 0;
}
int
mmap_user_strlen(struct process *process,
                 uintptr_t offset,
                 size_t max_strlen,
                 size_t *out_len)
{
    int res;

    struct mmap *mmap = process->mmap;
    DEBUG_ASSERT(KERNEL_ADDR(mmap));
    DEBUG_ASSERT(ptr_orderof(mmap) >= orderof(typeof(*mmap)));
    DEBUG_ASSERT(KERNEL_ADDR(mmap->vmem_region));
    DEBUG_ASSERT(ptr_orderof(mmap->vmem_region) >=
                 orderof(typeof(*mmap->vmem_region)));
    DEBUG_ASSERT(mmap->vmem_region->type == VMEM_REGION_TYPE_PAGED);
    DEBUG_ASSERT(mmap->vmem_region->size != 0);
    DEBUG_ASSERT(mmap->vmem_region->num_refs > 0);

    dprintk("mmap_user_strlen: PID(%ld), mmap=%p, offset=0x%lx, max=0x%lx\n",
            (sl_t)process->id,
            mmap,
            offset,
            max_strlen);

    mmap_lock_acquire(mmap);

    size_t len = 0;

    int done = 0;
    while(!done && len < max_strlen)
    {

        struct ptree_node *pnode;
        pnode = ptree_get_max_less_or_eq(&mmap->region_tree, offset);

        struct mmap_region *region =
            container_of(pnode, struct mmap_region, tree_node);

        if((pnode == NULL) || (offset >= region->size + pnode->key))
        {
            mmap_lock_release(mmap);
            return -EINVAL;
        }

        DEBUG_ASSERT(ptr_orderof(region->tree_node.key) >= VMEM_MIN_PAGE_ORDER);
        DEBUG_ASSERT(ptr_orderof(region->tree_node.key) <= 64);
        DEBUG_ASSERT(region->size > 0);

        dprintk("region=%p [%p-%p)\n",
                region,
                region->tree_node.key,
                region->tree_node.key + region->size);

        mmap_region_page_tree_lock_acquire(region);

        size_t region_offset = offset - region->tree_node.key;

        if((region->mmap_flags & MMAP_PROT_READ) == 0)
        {
            // The process is not allowed to read this page
            mmap_region_page_tree_lock_release(region);
            mmap_lock_release(mmap);
            return -EINVAL;
        }

        // Get or load the page
        pnode = ptree_get_max_less_or_eq(&region->page_tree, region_offset);
        struct mmap_page *page =
            container_of(pnode, struct mmap_page, tree_node);
        if((pnode == NULL) ||
           (region_offset >= (pnode->key + mpage_get_size(page->backing_page))))
        {
            dprintk("loading page (offset=%p)\n", region_offset);
            res = mmap_region_load_page(region, region_offset, &page);
            if(res)
            {
                mmap_region_page_tree_lock_release(region);
                mmap_lock_release(mmap);
                return res;
            }
        }
        else
        {
            dprintk("already had page (offset=%p)\n", region_offset);
        }

        struct ptree_node *iter = ptree_get_first(&region->page_tree);
        for(; iter != NULL; iter = ptree_get_next(iter))
        {
            struct mmap_page *iter_page =
                container_of(iter, struct mmap_page, tree_node);
        }

        if(page == NULL)
        {
            mmap_region_page_tree_lock_release(region);
            mmap_lock_release(mmap);
            return -EINVAL;
        }

        void __phys *page_paddr = mpage_get_phys(page->backing_page);
        DEBUG_ASSERT(ptr_orderof(page_paddr) >= VMEM_MIN_PAGE_ORDER);
        void *page_data = (void *)__va(page_paddr);

        uintptr_t page_offset = page->tree_node.key;
        size_t page_size = mpage_get_size(page->backing_page);
        size_t page_relative_offset = region_offset - page_offset;
        size_t room_avail = page_size - page_relative_offset;
        DEBUG_ASSERT(room_avail > 0);

        char *str_ptr = page_data + page_relative_offset;
        char *end_ptr = page_data + page_size;

        DEBUG_ASSERT((uintptr_t)str_ptr < (uintptr_t)end_ptr);

        while(str_ptr != end_ptr)
        {
            if(*str_ptr != '\0')
            {
                len++;
            }
            else
            {
                done = 1;
                break;
            }

            str_ptr++;
            offset++;
        }

        mmap_region_page_tree_lock_release(region);
    }

    mmap_lock_release(mmap);

    *out_len = len;
    return 0;
}

// Page Fault Handlers

int
mmap_not_present_page_fault_handler(struct mmap *mmap,
                                    struct mmap_region *region,
                                    uintptr_t region_offset)
{
    int res;

    dprintk("PID(%P) mmap_not_present_page_fault_handler: region->base=%p, "
            "region_offset=%p, region->file_offset=%p\n",
            region->tree_node.key,
            region_offset,
            region->file_offset);

    if(region_offset >= region->size)
    {
        goto unhandled;
    }

    struct ptree_node *pnode =
        ptree_get_max_less_or_eq(&region->page_tree, region_offset);

    struct mmap_page *page = container_of(pnode, struct mmap_page, tree_node);

    if(pnode == NULL || ((pnode->key + mpage_get_size(page->backing_page)) <= region_offset))
    {
        res = mmap_region_load_page(region, region_offset, &page);
        if(res)
        {
            goto unhandled;
        }
    }
    dprintk("mmap_not_present_page_fault_handler: page=%p\n", page);

    if(page == NULL)
    {
        goto unhandled;
    }

    res = mmap_region_map_page(region, page);
    if(res)
    {
        goto unhandled;
    }

    dprintk("mmap_not_present_page_fault_handler: mapped page!\n");
    return PAGE_FAULT_HANDLED;

unhandled:
    return PAGE_FAULT_UNHANDLED;
}

int
mmap_page_fault_handler(struct excp_state *state,
                        struct vmem_region_ref *ref,
                        uintptr_t offset,
                        unsigned long pf_flags,
                        void *priv_state)
{
    dprintk("PID(%P) mmap_page_fault_handler offset=%p, pf_flags={%s%s%s%s%s}\n",
            offset,
            pf_flags & PF_FLAG_READ ? "[READ]" : "",
            pf_flags & PF_FLAG_WRITE ? "[WRITE]" : "",
            pf_flags & PF_FLAG_EXEC ? "[EXEC]" : "",
            pf_flags & PF_FLAG_USERMODE ? "[USER]" : "",
            pf_flags & PF_FLAG_NOT_PRESENT ? "" : "[PRESENT]");
    struct mmap *mmap = priv_state;

    if((pf_flags & PF_FLAG_USERMODE) == 0)
    {
        arch_excp_dump_state(state, panic_printer());
        panic("Kernel attempted to access process mmap region directly! "
              "(mmap_offset=%p)\n",
              offset);
    }

    int res;
    mmap_lock_acquire(mmap);

    struct ptree_node *pnode;
    pnode = ptree_get_max_less_or_eq(&mmap->region_tree, offset);
    if(pnode == NULL)
    {
        mmap_lock_release(mmap);
        return PAGE_FAULT_UNHANDLED;
    }

    struct mmap_region *region =
        container_of(pnode, struct mmap_region, tree_node);

    mmap_region_page_tree_lock_acquire(region);

    uintptr_t region_offset = offset - region->tree_node.key;

    if(pf_flags & PF_FLAG_NOT_PRESENT)
    {
        res = mmap_not_present_page_fault_handler(mmap, region, region_offset);

        mmap_region_page_tree_lock_release(region);
        mmap_lock_release(mmap);
        return res;
    }

    pnode = ptree_get_max_less_or_eq(&region->page_tree, region_offset);
    DEBUG_ASSERT(KERNEL_ADDR(pnode));

    struct mmap_page *page = container_of(pnode, struct mmap_page, tree_node);

    if((page->flags & MMAP_PAGE_COPY_ON_WRITE) && (pf_flags & PF_FLAG_WRITE))
    {
        res = mmap_page_do_copy_on_write(region, page);
        if(res)
        {
            mmap_region_page_tree_lock_release(region);
            mmap_lock_release(mmap);
            return PAGE_FAULT_UNHANDLED;
        }

        mmap_region_page_tree_lock_release(region);
        mmap_lock_release(mmap);
        return PAGE_FAULT_HANDLED;
    }

    mmap_region_page_tree_lock_release(region);
    mmap_lock_release(mmap);
    return PAGE_FAULT_UNHANDLED;
}

// Waiting

int
mmap_wait_on(
        struct mmap *mmap,
        uintptr_t offset)
{
    return -EINTR;
}
int
mmap_wake_single(
        struct mmap *mmap,
        uintptr_t offset)
{
    return 0;
}
int
mmap_wake_all(
        struct mmap *mmap,
        uintptr_t offset)
{
    return 0;
}

// Cloning

// Should be called holding the region lock of "from"
static int
mmap_page_clone(struct mmap_region *from_region,
                struct mmap_page *from,
                struct mmap_region *to)
{
    int res;

    struct mmap_page *page = kzmalloc(sizeof(struct mmap_page), KM_KERNEL);
    if(page == NULL)
    {
        return -ENOMEM;
    }

    page->flags = from->flags;
    page->flags &= ~MMAP_PAGE_MAPPED;

    if(from_region->mmap_flags & (MMAP_PRIVATE|MMAP_ANON)) {
        page->flags |= MMAP_PAGE_COPY_ON_WRITE;
        from->flags |= MMAP_PAGE_COPY_ON_WRITE;
    }

    {
        struct mpage *backing_page = from->backing_page;
        DEBUG_ASSERT(KERNEL_ADDR(backing_page));

        res = mpage_get(backing_page);
        if(res)
        {
            kfree(page);
            return res;
        }

        page->backing_page = backing_page;
    }

    res = ptree_insert(&to->page_tree, &page->tree_node, from->tree_node.key);
    if(res)
    {
        mpage_put(page->backing_page);
        kfree(page);
        return res;
    }

    return 0;
}

// Should be called holding the mmap lock of "from"
static int
mmap_region_clone(struct mmap_region *from, struct mmap *to)
{
    int res;

    struct mmap_region *region =
        kzmalloc(sizeof(struct mmap_region), KM_KERNEL);
    if(region == NULL)
    {
        return -ENOMEM;
    }
    memset(region, 0, sizeof(struct mmap_region));

    region->mmap = to;

    mmap_region_page_tree_lock_acquire(region);

    region->size = from->size;
    region->file_offset = from->file_offset;
    region->mmap_flags = from->mmap_flags;
    region->fs_node = from->fs_node;
    if(region->fs_node)
    {
        fs_node_get(region->fs_node);
    }
    mmap_region_page_tree_lock_init(region);
    ptree_init(&region->page_tree);

    size_t region_offset = from->tree_node.key;

    res = ptree_insert(&to->region_tree, &region->tree_node, region_offset);
    if(res)
    {
        mmap_region_page_tree_lock_release(region);
        if(region->fs_node)
        {
            fs_node_put(region->fs_node);
        }
        kfree(region);
        return res;
    }

    struct ptree_node *pnode;
    for(pnode = ptree_get_first(&from->page_tree); pnode != NULL;
        pnode = ptree_get_next(pnode))
    {
        struct mmap_page *page =
            container_of(pnode, struct mmap_page, tree_node);
        res = mmap_page_clone(from, page, region);
        if(res)
        {
            eprintk("Failed to clone mmap page! err=%s\n", errnostr(res));
            mmap_region_page_tree_lock_release(region);
            // Our region will still be in the mmap just incomplete
            // (It should be freed on mmap destruction)
            return res;
        }
    }

    mmap_region_page_tree_lock_release(region);
    return 0;
}

int
mmap_clone(struct mmap *from, struct process *onto)
{
    int res;

    // mmap_dump(printk_printer(), from);

    res = mmap_create(from->vmem_region->size, onto);
    if(res)
    {
        return res;
    }
    struct mmap *mmap = onto->mmap;

    // No one should be able to access "onto->mmap" yet but just to be extra
    // safe...
    mmap_lock_acquire(mmap);
    mmap_lock_acquire(from);

    struct ptree_node *pnode;
    for(pnode = ptree_get_first(&from->region_tree); pnode != NULL;
        pnode = ptree_get_next(pnode))
    {
        struct mmap_region *region =
            container_of(pnode, struct mmap_region, tree_node);
        res = mmap_region_clone(region, mmap);
        if(res)
        {
            mmap_lock_release(mmap);
            mmap_lock_release(from);
            return res;
        }
    }

    ilist_node_t *proc_node;
    ilist_for_each(proc_node, &from->process_list)
    {
        struct process *process =
            container_of(proc_node, struct process, mmap_list_node);
        DEBUG_ASSERT(KERNEL_ADDR(process));
        struct vmem_map *map = process->thread.mem_map;
        res = vmem_flush_map(map);
        if(res)
        {
            wprintk("Failed to flush vmem map after cloning mmap! (err=%s) "
                    "(PID=%ld)\n",
                    errnostr(res),
                    process->id);
        }
    }

    mmap_lock_release(mmap);
    mmap_lock_release(from);

    // mmap_dump(printk_printer(), from);
    // mmap_dump(printk_printer(), onto->mmap);
    // dump_threads(do_printk);

    return 0;
}

static int
dump_mmap_page(struct printer *printer,
               struct mmap_region *region,
               struct mmap_page *page)
{
    fmt_print(printer, "\t\tPage [%p-%p] -> %p %s%s%s\n",
               region->tree_node.key + page->tree_node.key,
               region->tree_node.key + page->tree_node.key +
                   mpage_get_size(page->backing_page),
               mpage_get_phys(page->backing_page),
               page->flags & MMAP_PAGE_ANON ? "[ANON]" : "",
               page->flags & MMAP_PAGE_MAPPED ? "[MAPPED]" : "",
               page->flags & MMAP_PAGE_COPY_ON_WRITE ? "[COW]" : "");
    return 0;
}

static int
dump_mmap_region(struct printer *printer, struct mmap_region *region)
{
    int res;

    mmap_region_page_tree_lock_acquire(region);

    fmt_print(printer, "\tRegion [%p-%p] %s%s%s %s%s%s %s\n",
               (uintptr_t)region->tree_node.key,
               (uintptr_t)region->tree_node.key + region->size,
               region->mmap_flags & MMAP_PROT_READ ? "[READ]" : "",
               region->mmap_flags & MMAP_PROT_WRITE ? "[WRITE]" : "",
               region->mmap_flags & MMAP_PROT_EXEC ? "[EXEC]" : "",
               region->mmap_flags & MMAP_ANON ? "[ANON]" : "",
               region->mmap_flags & MMAP_SHARED ? "[SHARED]" : "",
               region->mmap_flags & MMAP_PRIVATE ? "[PRIVATE]" : "",
               mmap_region_get_name(region));

    struct ptree_node *pnode;
    for(pnode = ptree_get_first(&region->page_tree); pnode != NULL;
        pnode = ptree_get_next(pnode))
    {
        struct mmap_page *page =
            container_of(pnode, struct mmap_page, tree_node);
        res = dump_mmap_page(printer, region, page);
        if(res)
        {
            mmap_region_page_tree_lock_release(region);
            return res;
        }
    }

    mmap_region_page_tree_lock_release(region);
    return 0;
}

int
mmap_dump(struct printer *printer, struct mmap *mmap)
{
    int res;
    mmap_lock_acquire(mmap);

    struct ptree_node *pnode;
    for(pnode = ptree_get_first(&mmap->region_tree); pnode != NULL;
        pnode = ptree_get_next(pnode))
    {
        struct mmap_region *region =
            container_of(pnode, struct mmap_region, tree_node);
        mmap_region_page_tree_lock_acquire(region);
        res = dump_mmap_region(printer, region);
        if(res)
        {
            mmap_region_page_tree_lock_release(region);
            return res;
        }
        mmap_region_page_tree_lock_release(region);
    }

    mmap_lock_release(mmap);
    return 0;
}

