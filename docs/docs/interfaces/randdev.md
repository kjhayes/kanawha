
Kanawha Randomness Device Interface
===================================

## Randomness Device Methods

Every randomness device driver must implement the following methods.

### rand_dev_read

```C
ssize_t rand_dev_read(struct rand_dev *dev, void *buffer, size_t amount);
```

Read up to `amount` random (or pseudo-random) bytes from the device into `buffer`.

Returns the number of bytes read on success. a negative `errno` on error.

May block until at least 1 random byte is available.

## Sysfs

Every registered randomness device will appear as a file under the `randdev` sysfs mount.

