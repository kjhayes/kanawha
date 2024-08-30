
# Kanawha Kernel

(Pronounced "Kuh-Nah")

This is a simple hobby kernel I (Kevin Hayes) have been writing in my free time.

## Directory Structure

- kernel
    Contains the core of the kernel, which is statically linked together as a single module,
    and loaded completely at boot. This should be kept as small as possible.

- module
    Contains kernel "modules" which are linked into ELF object files and can be loaded and
    unloaded by the kernel during runtime. Modules can then be statically linked into the 
    kernel to be loaded during boot if needed, but it is preferable to use a boot filesystem
    or initramdisk to load the module during boot instead.

- arch/ARCH/kernel
    Contains architecture specific code to be linked into the core kernel

- arch/ARCH/module
    Contains architecture specific modules

- include/
    Root of the header file structure which defines kernel API's, passed with "-I" during compilation

- include/module
    Contains module header files, passed with "-I" during compilation. This means to reference 
    "include/module/my-mod/file.h" either "#include <module/my-mod/file.h>" or "#include <my-mod/file.h>"
    can be used in the kernel and modules, but the latter is preferable.

