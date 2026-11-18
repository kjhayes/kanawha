
# Kanawha Kernel

![Logo](images/logo.png)

A simple hobby kernel I'm ([Kevin](https://kjhayes.org)) writing in my free time.

## Features (Incomplete List)

- Architectures
    - x64
    - ARM64
    - RISCV64

- Kernel
    - SMP Support
    - Memory Management Hierarchy
        - Physical Buddy Allocator (`page_alloc`)
        - Virtual Memory Freelist Heap (`kmalloc`)
    - Virtual Filesystem and sysfs

- Drivers
    - Filesystems
        - Ext2
        - (ex)FAT
        - CPIO (mostly for initrd)
    - Block Devices
        - IDE
        - NVME
        - Virtio Block
        - Virtio SCSI
    - Display Devices
        - VGA (Full Modesetting Support)
        - Virtio GPU
    - Input Devices
        - PS/2 Keyboard/Mouse
        - Virtio Input
        - Most 8250 Compatible Serial Ports
        - ARM PL011
        - USB Keyboard (XHCI: Very incomplete)
    - Networking
        - Virtio Networking (Very incomplete)

- Userspace
    - (somewhat) POSIX Compliant C Standard Library
    - Various Simple Programs (`sh`, `cp`, `ls`, etc.)

## Building the Kernel
On most x86_64 linux distributions
```
make defconfig/x64
make
```
will build the kernel as `build/kanawha.o`.
Then running
```
make isoimage
```
will generate a `build/kanawha.iso` disk image with a small
initial ramdisk containing a small number of userspace programs.
This can then be installed onto a USB drive to boot the kernel
on a physical machine.

## Configuring the Kernel
To configure a custom kernel run `make menuconfig`.

A number of default configurations can be found in
`setups/*/defconfig` or `setups/*/%_defconfig` or loaded
by running `make defconfig/*` or `make defconfig/*/%` respectively.

## Running Under QEMU
For testing the kernel (assuming QEMU is installed)
```
make qemu
```
will run `qemu-system-x86_64` with a fairly standard
configuration (the specifics of which can be found
in the file `scripts/make/qemu.mk`).

## Documentation
(Incomplete) Documentation for the kernel can be found at (https://kjhayes.org/kanawha)

