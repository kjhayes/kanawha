
Kanawha Character Device Interface
==================================

## Character Device Methods 

The following methods are defined which must be implemented by any character device driver.

### char_dev_read

```C
size_t char_dev_read(struct char_dev *dev, void *buffer, size_t amount);
```

Attempt to read up to `amount` bytes from the character device into `buffer`.
The `size_t` return value should be the number of bytes read.

`char_dev_read` may block until at least 1 byte is read.

### char_dev_write

```C
size_t char_dev_write(struct char_dev *dev, void *buffer, size_t amount);
```

Attempt to write up to `amount` bytes from the character device into `buffer`.
The `size_t` return value should be the number of bytes written.

`char_dev_write` may block until at least 1 byte is written.

### char_dev_flush

```C
size_t char_dev_flush(struct char_dev *dev, void *buffer, size_t amount);
```

Ensure that any bytes which are pending/queued to be written are fully written.

Should block until this can be gaurenteed.

## Additional Notes
Currently there is no way for a character device to signal that it is blocking or non-blocking.
As such, all NON_BLOCKING read/write requests to a character device will always fail.

## Sysfs

All registered character devices will appear as files in the `chardev` sysfs mount.

