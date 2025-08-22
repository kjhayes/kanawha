
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <drivers/fs/ext2/ext2.h>
#include <drivers/fs/ext2/mount.h>
#include <drivers/fs/ext2/node.h>
#include <drivers/fs/ext2/group.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>
#include <kanawha/init.h>

struct fs_node_ops
ext2_file_node_ops = {
    .read_page = ext2_fs_node_read_page,
    .write_page = ext2_fs_node_write_page,

    .load_page = fs_node_load_page_read_alloc,
    .unload_page = fs_node_unload_page_free,
    .flush_page = fs_node_flush_page_write,
    
    .flush = ext2_fs_node_flush,

    .getattr = ext2_fs_node_getattr,
    .setattr = ext2_fs_node_setattr,
};
FS_NODE_OPS_INIT_UNDEF(ext2_file_node_ops);

struct fs_file_ops
ext2_file_file_ops = {
    .read = fs_file_paged_read,
    .write = fs_file_paged_write,
    .seek = fs_file_paged_seek,
    .flush = fs_file_paged_flush,
};
FS_FILE_OPS_INIT_UNDEF(ext2_file_file_ops);

