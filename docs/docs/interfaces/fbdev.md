
Kanawha Framebuffer Device Interface
====================================

## Framebuffer Modes

Every framebuffer device should have at least 1 "mode" of operation.
How many/what format of modes are presented is device/driver specific,
but the numbering should begin from mode zero (which must always exist)
and increase contiguously from zero.

Modes can be thought of as a collection of layers of the same resolution with
varying formats (RGBA,RBGA,Mono,etc.).

Modes are described using `struct fb_mode_info`, `struct fb_layer_info` and the macros defiend in `uapi/fb.h`.

## Framebuffer Device Methods

Every framebuffer device driver is expected to implement the following methods.

### fb_dev_get_mode_info

```C
struct fb_mode_info *
fb_dev_get_mode_info(struct fb_dev *dev, size_t index);
```

Returns a pointer to `struct fb_mode_info` describing mode `index` of the device,
or returns `NULL` if no mode `index` exists.

If non-`NULL` the pointer must remain valid until a call to `fb_dev_put_mode_info` with the same index and device.

### fb_dev_put_mode_info

```C
int
fb_dev_put_mode_info(struct fb_dev *dev, size_t index);
```

Must be called after `fb_dev_get_mode_info` to release the `struct fb_mode_info` associated with mode `index`.

### fb_dev_set_mode

```C
int
fb_dev_set_mode(struct fb_dev *dev, size_t index);
```

Changes the current mode of the framebuffer device to `index`.
The driver may assume this function is only called when the buffer of `dev` is unloaded.

Returns 0 on success or an `errno` on failure.

### fb_dev_get_mode

```C
ssize_t
fb_dev_get_mode(struct fb_dev *dev);
```

Get the current mode of the framebuffer device.

Returns positive or zero mode, or a negative `errno` if the driver fails
to determine the current mode of the device or the device is in an
invalid/unconfigured state.

### fb_dev_load_buffer

```C
int
fb_dev_load_buffer(struct fb_dev *dev, void __phys **base_out);
```

Load backing memory for the framebuffer.
The size of the buffer should be at least as large as the current mode
`struct fb_mode_info` field `buffer_size` indicates.
The buffer must also be aligned to at least `VMEM_MIN_PAGE_ORDER`.

However the buffer size does not need to be a multiple of `VMEM_MIN_PAGE_ORDER`.
This is because kernel subsystem which manages framebuffer devices to present
them to userspace will handle mapping strange sizes of framebuffers correctly.
Note though, that if the buffer can be a multiple of `VMEM_MIN_PAGE_ORDER`,
for performance reasons it should be.

The driver may assume that there will only one call to `fb_dev_load_buffer`
between calls to `fb_dev_unload_buffer`.

### fb_dev_unload_buffer

```C
int
fb_dev_unload_buffer(struct fb_dev *dev, void __phys **base);
```

Unloads the buffer previously loaded by `fb_dev_load_buffer`.
`base` must be the same pointer as was returned by the last call to `fb_dev_load_buffer` in `base_out`.

`fb_dev_unload_buffer` may flush the buffer, but should not if it is not required.

Returns 0 on success and a negative `errno` on failure.

### fb_dev_flush_buffer

```C
int
fb_dev_flush_buffer(struct fb_dev *dev);
```

Flush the currently loaded buffer to the display.

The driver may assume that the buffer is currently loaded when a call is made to
`fb_dev_flush_buffer`.
The driver may also flush the buffer at any point when it is loaded. Though it
is only required to during an explicit call to `fb_dev_flush_buffer`.

Returns 0 on success or a negative `errno` on failure.

## Sysfs

All registered framebuffer devices should appear as a file under the `fbdev` sysfs mount.

The root file of the device should give direct access to the backing buffer for the device.
The root file should also have two children: `*/mode` and `*/info`.

Reading `*/mode` returns the current mode of the device as a decimal number string.
Writing `*/mode` with a integer string will attempt to set the mode of the device.
This may fail if the device is pinned or if the mode does not exist, so the `*/mode` should
be read again after writing to verify that the mode has actually be set correctly.

Reading `*/info` should return the same data as the C struct `fb_dev_mode_info` for the last integer mode written to `*/info`. If `*/info` has size zero, this indicates an issue with the last integer string written to `*/info` (most likely that the mode does not exist).
Writing `*/info` does not change the current mode of the device, and can be used safely to probe what modes are available on the device.

