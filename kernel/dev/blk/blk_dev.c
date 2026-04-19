
#include <kanawha/dev/blk.h>
#include <kanawha/init.h>
#include <kanawha/page_alloc.h>

static int
blk_dev_init(struct blk_dev *dev)
{
    printk("blk_dev registered: %s\n", blk_dev_get_name(dev));
    return 0;
}

static int
blk_dev_deinit(struct blk_dev *dev)
{
    printk("blk_dev unregistered: %s\n", blk_dev_get_name(dev));
    return 0;
}

DEFINE_DEV_TYPE(blk_dev, dev, blk_dev_init, blk_dev_deinit);

int
blk_dev_write_using_pwrite(struct blk_dev *dev,
                           void *ptr,
                           size_t base_sector,
                           size_t num_sectors)
{
    int res;
    order_t sector_order = blk_dev_sector_order(dev);

    // We do a sector at a time
    void __phys *phys_buffer;
    res = page_alloc(sector_order, &phys_buffer, PAGE_ALLOC_64BIT);
    if(res)
    {
        return res;
    }

    for(size_t i = 0; i < num_sectors; i++)
    {
        memcpy_vp(phys_buffer, ptr + (i << sector_order), 1UL << sector_order);
        res = blk_dev_pwrite(dev, phys_buffer, base_sector + i, 1);
        if(res)
        {
            page_free(sector_order, phys_buffer);
            return res;
        }
    }

    page_free(sector_order, phys_buffer);
    return 0;
}

int
blk_dev_read_using_pread(struct blk_dev *dev,
                         void *ptr,
                         size_t base_sector,
                         size_t num_sectors)
{
    int res;
    order_t sector_order = blk_dev_sector_order(dev);

    // We do a sector at a time
    void __phys *phys_buffer;
    res = page_alloc(sector_order, &phys_buffer, PAGE_ALLOC_64BIT);
    if(res)
    {
        return res;
    }

    for(size_t i = 0; i < num_sectors; i++)
    {
        res = blk_dev_pread(dev, phys_buffer, base_sector + i, 1);
        if(res)
        {
            page_free(sector_order, phys_buffer);
            return res;
        }
        memcpy_pv(ptr + (i << sector_order), phys_buffer, 1UL << sector_order);
    }

    page_free(sector_order, phys_buffer);
    return 0;
}

int
blk_dev_pwrite_using_write(struct blk_dev *dev,
                           void __phys *ptr,
                           size_t base_sector,
                           size_t num_sectors)
{
    int res;
    order_t sector_order = blk_dev_sector_order(dev);

    void *virt_buffer = kmalloc(1UL << sector_order, KM_KERNEL);
    if(virt_buffer == NULL)
    {
        return -ENOMEM;
    }

    for(size_t i = 0; i < num_sectors; i++)
    {
        memcpy_pv(virt_buffer, ptr + (i << sector_order), 1UL << sector_order);
        res = blk_dev_write(dev, virt_buffer, base_sector + i, 1);
        if(res)
        {
            kfree(virt_buffer);
            return res;
        }
    }

    kfree(virt_buffer);
    return 0;
}

int
blk_dev_pread_using_read(struct blk_dev *dev,
                         void __phys *ptr,
                         size_t base_sector,
                         size_t num_sectors)
{
    int res;
    order_t sector_order = blk_dev_sector_order(dev);

    void *virt_buffer = kmalloc(1UL << sector_order, KM_KERNEL);
    if(virt_buffer == NULL)
    {
        return -ENOMEM;
    }

    for(size_t i = 0; i < num_sectors; i++)
    {
        res = blk_dev_read(dev, virt_buffer, base_sector + i, 1);
        if(res)
        {
            kfree(virt_buffer);
            return res;
        }
        memcpy_vp(ptr + (i << sector_order), virt_buffer, 1UL << sector_order);
    }

    kfree(virt_buffer);
    return 0;
}

int
blk_dev_nop_flush(struct blk_dev *dev, unsigned long flags)
{
    return 0;
}

#ifdef CONFIG_LOG_BLKDEV_REGISTRY_ON_LAUNCH
static int
dump_blk_dev_on_launch(void)
{
    return dump_blk_dev_registry(do_printk);
}
declare_init(launch, dump_blk_dev_on_launch);
#endif
