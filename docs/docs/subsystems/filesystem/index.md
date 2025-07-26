
Kanawha Filesystem Subsystem
============================

## struct fs_mount

`fs_mount` represent a specific instance of a filesystem, they provide the mapping
from integer inodes to `fs_node` structures and are responsible for loading/unloading
them.

The mount provides a simple `load`/`unload` interface and reference counting is handled
by the generic filesystem subsystem to simplify filesystem drivers.

## struct fs_node

`fs_node`s represent the inode of an underlying filesystem.
Every mount contains a mapping from integers to `fs_node`,
and most file operations occur on them.

## struct fs_path

`fs_path` represent a node in the filesystem namespace.

## struct file

Every file descriptor opened by a process corresponds to a `file` structure in the kernel.

