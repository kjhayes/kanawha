
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/ext2/ext2.h>
#include <kanawha/fs/ext2/mount.h>
#include <kanawha/fs/ext2/node.h>
#include <kanawha/fs/ext2/group.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>
#include <kanawha/init.h>

struct fs_node_ops
ext2_file_node_ops = {
    .read_page = ext2_fs_node_read_page,
    .write_page = ext2_fs_node_write_page,
    .getattr = ext2_fs_node_getattr,
    .setattr = ext2_fs_node_setattr,
    .flush = ext2_fs_node_flush,

    .mkfile = fs_node_cannot_mkfile,
    .mkfifo = fs_node_cannot_mkfifo,
    .mkdir = fs_node_cannot_mkdir,
    .link = fs_node_cannot_link,
    .symlink = fs_node_cannot_symlink,
    .unlink = fs_node_cannot_unlink,
};

struct fs_file_ops
ext2_file_file_ops = {
    .read = fs_file_paged_read,
    .write = fs_file_paged_write,
    .seek = fs_file_paged_seek,
    .flush = fs_file_node_flush,

    .dir_next = fs_file_cannot_dir_next,
    .dir_begin = fs_file_cannot_dir_begin,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};
