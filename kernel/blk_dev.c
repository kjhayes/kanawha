
#include <kanawha/blk_dev.h>
#include <kanawha/init.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <kanawha/device.h>
#include <kanawha/printk.h>
#include <kanawha/vmem.h>
#include <kanawha/stddef.h>
#include <kanawha/page_alloc.h>

static DECLARE_SPINLOCK(blk_dev_tree_lock);
static DECLARE_STREE(blk_dev_tree);

struct blk_dev_disk
{
    struct blk_dev *dev;
    size_t index;

    spinlock_t tree_lock;
    struct ptree page_tree;
    struct ptree sector_tree;

    order_t page_order;
    unsigned long page_flags;
};

struct blk_page {
    struct cached_anon_page page;
    struct ptree_node node;
    struct blk_dev_disk *disk;
    int refs;
};

struct blk_sector {
    struct cached_subpage subpage;
    struct ptree_node node;
    struct blk_dev_disk *disk;
    struct blk_page *blk_page;
};

static int
blk_page_flush(struct cached_page *page)
{
    int res;
    struct cached_anon_page *anon =
        container_of(page, struct cached_anon_page, page);
    struct blk_page *blk_page =
        container_of(anon, struct blk_page, page);
    
    struct blk_dev_disk *disk = blk_page->disk;

    size_t sectors_per_page = (1ULL << (page->order - disk->dev->sector_order));

    void *page_addr = (void*)__va(cached_page_addr(page));

    size_t pfn = blk_page->node.key;
    size_t base_sector = pfn * sectors_per_page;

    size_t num_sectors;
    res = blk_dev_num_sectors(disk->dev, disk->index, &num_sectors);
    if(res) {
        return res;
    }

    size_t max_sectors = num_sectors - base_sector;
    size_t num_to_write = max_sectors < sectors_per_page ? max_sectors : sectors_per_page;

    return blk_dev_write_direct(
            disk->dev,
            disk->index,
            page_addr,
            base_sector,
            num_to_write);   
}

static int
blk_page_populate(struct cached_page *page)
{
    int res;
    struct cached_anon_page *anon =
        container_of(page, struct cached_anon_page, page);
    struct blk_page *blk_page =
        container_of(anon, struct blk_page, page);
    
    struct blk_dev_disk *disk = blk_page->disk;

    size_t sectors_per_page = (1ULL << (page->order - disk->dev->sector_order));

    void *page_addr = (void*)__va(cached_page_addr(page));
    size_t pfn = blk_page->node.key;
    size_t base_sector = pfn * sectors_per_page;

    size_t num_sectors;
    res = blk_dev_num_sectors(disk->dev, disk->index, &num_sectors);
    if(res) {
        return res;
    }

    size_t max_sectors = num_sectors - base_sector;
    size_t num_to_read = max_sectors < sectors_per_page ? max_sectors : sectors_per_page;

    return blk_dev_read_direct(
            disk->dev,
            disk->index,
            page_addr,
            base_sector,
            num_to_read);
}

static struct cached_page_ops
blk_page_ops = {
    .flush = blk_page_flush,
    .populate = blk_page_populate,
    .alloc_backing = NULL, // These will be set by the cached_anon_page framework
    .free_backing = NULL,
};

// Assumes the disk lock is held
static struct blk_page *
__blk_disk_alloc_page(
        struct blk_dev_disk *disk,
        size_t pfn)
{
    struct blk_page *pg = kmalloc(sizeof(struct blk_page));
    if(pg == NULL) {
        return pg;
    }
    memset(pg, 0, sizeof(struct blk_page));

    pg->disk = disk;
    pg->refs = 0;
    
    int res = init_cached_anon_page(
            &pg->page,
            &blk_page_ops,
            disk->page_order,
            disk->page_flags);
    if(res) {
        kfree(pg);
        return NULL;
    }

    ptree_insert(&disk->page_tree, &pg->node, pfn);

    return pg;
}

// Assumes the disk lock is held
static void
__free_blk_page(
        struct blk_page *pg)
{
    struct blk_dev_disk *disk = pg->disk;
    ptree_remove(&disk->page_tree, pg->node.key);

    kfree(pg);
}

// Assumes the disk lock is held
static struct blk_page *
__blk_disk_get_page(struct blk_dev_disk *disk, size_t pfn)
{
    struct ptree_node *node;
    struct blk_page *page;
    node = ptree_get(&disk->page_tree, pfn);
    if(node == NULL) {
        page = __blk_disk_alloc_page(disk, pfn);
    } else {
        page = container_of(node, struct blk_page, node);
    }

    page->refs++;

    return page;
}

static void
__blk_disk_put_page(struct blk_page *page)
{
    page->refs--;
}

// Assumes the disk lock is held
static struct blk_sector * 
__blk_disk_alloc_sector(
        struct blk_dev_disk *disk,
        struct blk_page *page,
        size_t sector_index)
{
    struct blk_sector *sector = kmalloc(sizeof(struct blk_sector));
    if(sector == NULL) {
        return sector;
    }
    memset(sector, 0, sizeof(struct blk_sector));

    sector->disk = disk;
    sector->blk_page = page;

    size_t sectors_per_page = (1ULL << (disk->page_order - disk->dev->sector_order));
    size_t page_offset = (sector_index % sectors_per_page) << disk->dev->sector_order;

    int res = init_cached_subpage(
            &sector->subpage,
            disk->dev->sector_order,
            page_offset,
            &page->page.page);

    if(res) {
        kfree(sector);
        return NULL;
    }

    ptree_insert(&disk->sector_tree, &sector->node, sector_index);

    return sector;
}

static int 
__blk_disk_free_sector(
        struct blk_sector *sector)
{
    ptree_remove(&sector->disk->sector_tree, sector->node.key);
    kfree(sector);
    return 0;
}

static int
__init_blk_dev_disk(
        struct blk_dev_disk *disk,
        struct blk_dev *dev,
        size_t index)
{
    disk->dev = dev;
    disk->index = index;

    // TODO: provide an interface to set these
    disk->page_order = 12;
    disk->page_flags = 0;

    ptree_init(&disk->page_tree);
    ptree_init(&disk->sector_tree);
    spinlock_init(&disk->tree_lock);
    return 0;
}

int
register_blk_dev(
        struct blk_dev *blk,
        const char *name,
        struct blk_driver *driver,
        struct device *device,
        order_t sector_order,
        size_t num_disks)
{
    spin_lock(&blk_dev_tree_lock);
    struct stree_node *existing = stree_get(&blk_dev_tree, name);
    if(existing != NULL) {
        spin_unlock(&blk_dev_tree_lock);
        return -EEXIST;
    }

    blk->device = device;
    blk->driver = driver;
    blk->sector_order = sector_order;

    blk->num_disks = num_disks;

    blk->disks = kmalloc(sizeof(struct blk_dev_disk) * num_disks);
    if(blk->disks == NULL) {
        spin_unlock(&blk_dev_tree_lock);
        return -ENOMEM;
    }
    memset(blk->disks, 0, sizeof(struct blk_dev_disk) * num_disks);

    for(size_t i = 0; i < blk->num_disks; i++) {
        int res;
        res = __init_blk_dev_disk(
                &blk->disks[i],
                blk,
                i);
        if(res) {
            spin_unlock(&blk_dev_tree_lock);
            kfree(blk->disks);
            return res;
        }
    }

    blk->blk_dev_node.key = name;
    stree_insert(&blk_dev_tree, &blk->blk_dev_node);

    spin_unlock(&blk_dev_tree_lock);
    return 0;
}

int
unregister_blk_dev(struct blk_dev *dev)
{
    // TODO
    return -EUNIMPL;
}

struct blk_dev *
blk_dev_find(const char *name) {
    spin_lock(&blk_dev_tree_lock);
    struct stree_node *node = stree_get(&blk_dev_tree, name);
    spin_unlock(&blk_dev_tree_lock);
    if(node == NULL) {
        return NULL;
    }
    return container_of(node, struct blk_dev, blk_dev_node);
}

struct cached_page *
blk_dev_get_sector(
        struct blk_dev *dev,
        size_t disk_index,
        size_t sector_index)
{
    int res;

    struct blk_dev_disk *disk = &dev->disks[disk_index];

    struct blk_sector *sector = NULL;

    struct ptree_node *node;

    spin_lock(&disk->tree_lock);
    node = ptree_get(&disk->sector_tree, sector_index);

    if(node == NULL) {
        size_t pfn = (sector_index << dev->sector_order) >> disk->page_order;
        struct blk_page *page = __blk_disk_get_page(disk, pfn);
        if(page == NULL) {
            page = __blk_disk_alloc_page(disk, pfn);
            if(page == NULL) {
              // OOM
              res = -ENOMEM;
              goto err;
            }
        }

        sector = __blk_disk_alloc_sector(disk, page, sector_index);
        if(sector == NULL) {
            __blk_disk_put_page(page);
            res = -ENOMEM;
            goto err;
        }
        res = cached_page_get(&sector->subpage.page);
        if(res) {
            __blk_disk_put_page(page);
            goto err;
        }

    } else {
        sector = container_of(node, struct blk_sector, node);
        res = cached_page_get(&sector->subpage.page);
        if(res) {
            goto err;
        }
    }
    spin_unlock(&disk->tree_lock);

    return &sector->subpage.page;

err:
    spin_unlock(&disk->tree_lock);
    return NULL;
}

int
blk_dev_put_sector(struct cached_page *page)
{
    int res;
    struct cached_subpage *subpage =
        container_of(page, struct cached_subpage, page);
    struct blk_sector *sector =
        container_of(subpage, struct blk_sector, subpage);

    struct blk_dev_disk *disk = sector->disk;

    spin_lock(&disk->tree_lock);

    res = cached_page_put(page);
    if(res) {goto err;}

    if(page->pins == 0) {
        // We can free the sector page
        __blk_disk_put_page(sector->blk_page);
        res = __blk_disk_free_sector(sector);
        if(res) {
            goto err;
        } 
    }

    spin_unlock(&disk->tree_lock);

    return 0;
err:
    spin_unlock(&disk->tree_lock);
    return res;
}

/*
 * Cached Read/Write
 */

int
blk_dev_read(
        struct blk_dev *dev,
        size_t disk_index,
        void *buffer,
        size_t offset,
        size_t *len)
{
    size_t read = 0;
    struct blk_dev_disk *disk = &dev->disks[disk_index];

    int res;

    while(read < *len) {
        dprintk("blk_dev_read(read=0x%x, *len=0x%x)\n",
                read, *len);
        size_t pfn = offset >> disk->page_order;
        size_t page_offset = offset - (pfn << disk->page_order);

        size_t room_left = (1ULL<<disk->page_order) - page_offset;
        size_t to_read = *len - read;
        if(room_left > to_read) {
            room_left = to_read;
        }

        dprintk("room_left=0x%x, page_offset=0x%x\n", room_left, page_offset);

        spin_lock(&disk->tree_lock);
        struct blk_page *page =
            __blk_disk_get_page(disk, pfn);
        if(page == NULL) {
            res = -EINVAL;
            goto err;
        }

        res = cached_page_get(&page->page.page);
        if(res) {
            goto err;
        }
        void *page_data = (void*)__va(cached_page_addr(&page->page.page));
        page_data += page_offset;
        memcpy(buffer, page_data, room_left);
        res = cached_page_put(&page->page.page);
        if(res) {
            goto err;
        }

        __blk_disk_put_page(page);
        spin_unlock(&disk->tree_lock);

        buffer += room_left;
        offset += room_left;
        read += room_left;
    }
    return 0;

err:
    *len = read;
    return res;
}

int
blk_dev_write(
        struct blk_dev *dev,
        size_t disk_index,
        void *buffer,
        size_t offset,
        size_t *len)
{
    size_t read = 0;
    struct blk_dev_disk *disk = &dev->disks[disk_index];

    int res;

    while(read < *len) {
        size_t pfn = offset >> disk->page_order;
        size_t page_offset = offset - (pfn << disk->page_order);

        size_t room_left = (1ULL<<disk->page_order) - page_offset;
        size_t to_read = *len - read;
        if(room_left > to_read) {
            room_left = to_read;
        }

        spin_lock(&disk->tree_lock);
        struct blk_page *page =
            __blk_disk_get_page(disk, pfn);
        if(page == NULL) {
            res = -EINVAL;
            goto err;
        }

        cached_page_get(&page->page.page);
        void *page_data = (void*)__va(cached_page_addr(&page->page.page));
        page_data += page_offset;
        memcpy(page_data, buffer, room_left);
        cached_page_put(&page->page.page);

        __blk_disk_put_page(page);
        spin_unlock(&disk->tree_lock);

        buffer += room_left;
        offset += room_left;
        read += room_left;
    }
    return 0;

err:
    *len = read;
    return res;
}

/*
 * Direct Access API
 */

int
blk_dev_read_direct(
        struct blk_dev *dev,
        size_t disk_index,
        void *buffer,
        size_t base_sector,
        size_t num_sectors)
{
    struct blk_dev_request req;
    req.type = BLK_DEV_REQ_READ;
    req.disk = disk_index;
    atomic_bool_set_relaxed(&req.complete, 0);
    req.read_input.buffer_to = buffer;
    req.read_input.sector_from = base_sector;
    req.read_input.num_sectors = num_sectors;

    int res = blk_dev_request(dev, &req);
    if(res) {
        return res;
    }

    if(!atomic_bool_check(&req.complete)) {
        // We returned 0 but didn't complete the request?
        // "request" should be synchronous, this is an error
        return -EINVAL;
    }

    return 0;
}

int
blk_dev_write_direct(
        struct blk_dev *dev,
        size_t disk_index,
        void *buffer,
        size_t base_sector,
        size_t num_sectors)
{
    struct blk_dev_request req;
    req.type = BLK_DEV_REQ_WRITE;
    req.disk = disk_index;
    atomic_bool_set_relaxed(&req.complete, 0);
    req.write_input.buffer_from = buffer;
    req.write_input.sector_to = base_sector;
    req.write_input.num_sectors = num_sectors;

    int res = blk_dev_request(dev, &req);
    if(res) {
        return res;
    }

    if(!atomic_bool_check(&req.complete)) {
        // We returned 0 but didn't complete the request?
        // "request" should be synchronous, this is an error
        return -EINVAL;
    }

    return 0;
}
