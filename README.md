
# Kanawha Kernel

![Logo](images/logo.png)

A simple hobby kernel I'm ([Kevin](https://kjhayes.github.io)) writing in my free time.

## Running the Kernel

On most x86_64 linux distributions
```
make x64/defconfig
make
```
will build the kernel as `build/kanawha.o`.
Then running
```
make isoimage
```
will generate `build/kanawha.iso` which can be
installed onto a USB drive to boot the kernel on
an x64 machine.

For testing the kernel (assuming QEMU is installed)
```
make qemu
```
will run `qemu-system-x86_64` with a fairly standard
configuration (the specifics of which can be found
in the file `scripts/make/qemu.mk`).

More kernel default configurations can be found in
`setups/*/defconfig` or loaded by running `make */defconfig`
(notably `make riscv64/defconfig` for testing the RISC-V support
in Kanawha).

To configure a custom kernel run
```
make menuconfig
```
to change any number of settings.

## Documentation
(Incomplete) Documentation for the kernel can be found at (https://kjhayes.github.io/kanawha)

