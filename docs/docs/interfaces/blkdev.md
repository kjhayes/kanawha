
Kanawha Block Device Interface
==============================

## Block Device Methods

The following methods are defined which must be implemented by any block device driver.

### blk_dev_read

```C
int blk_dev_read(struct blk_dev *dev, void *data, size_t base_sector, size_t num_sectors);
```

Read `num_sectors` sectors into `data` from the block device, starting at `base_sector`.

Returns 0 on success or an `errno` value on error.

Should block until all sectors have been read.

### blk_dev_write

```C
int blk_dev_write(struct blk_dev *dev, void *data, size_t base_sector, size_t num_sectors);
```

Write `num_sectors` sectors from `data` back to the block device, starting at `base_sector`.

Returns 0 on success or an `errno` value on error.

Should block until the data is fully written back to the device.

## Additional Notes

The current block device interface is extremely simple.
Evenetually this will certainly need to be extended to
at least support async read/write and flushing those
requests to the device at a later point.

## Sysfs

All registered block devices will appear as files in the `blkdev` sysfs mount.

