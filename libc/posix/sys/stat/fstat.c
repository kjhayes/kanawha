
#include <kanawha/sys-wrappers.h>
#include <kanawha/attr.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int
fstat(
    int filedes,
    struct stat * buffer)
{
    int res;

    memset(buffer, 0, sizeof(*buffer));

    buffer->st_dev = 0;

    { // st_ino
    size_t inode_index;
    res = kanawha_sys_fattr(filedes, FILE_ATTR_INODE, &inode_index);
    if(res) {
        buffer->st_ino = 0;
    } else {
        buffer->st_ino = inode_index;
    }
    }

    { // st_size
    size_t size;
    res = kanawha_sys_fattr(filedes, FILE_ATTR_DATASIZE, &size);
    if(res) {
        buffer->st_size = 0;
    } else {
        buffer->st_size = size;
    }
    }

    { // st_blksize
    size_t blksize;
    res = kanawha_sys_fattr(filedes, FILE_ATTR_PAGESIZE, &blksize);
    if(res) {
        buffer->st_blksize = 0;
    } else {
        buffer->st_blksize = blksize;
    }
    }

    buffer->st_mode = S_IRWXU|S_IRWXG|S_IRWXO; // No permission checking currently
    buffer->st_nlink = 1;
    buffer->st_uid = 0;
    buffer->st_gid = 0;
    buffer->st_rdev = 0;


    // TODO
    buffer->st_mode = S_IFDIR;

    return 0;
}

