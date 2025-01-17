
Building Kanawha
================

To build the kernel ensure that there is a valid ``.config`` file
in the root directory, or generate one with::

    $ make defconfig

or modify the current config with::

    $ make menuconfig

Once there is a valid ``.config`` all you need to do is run::

    $ make

and a kernel binary should be built at ``build/kanawha.o``.

Buildsystem Details
===================

Kanawha has a custom buildsystem, which is heavily
inspired by the design of "kbuild" from the Linux
kernel.

