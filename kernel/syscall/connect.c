
#include <kanawha/syscall.h>
#include <kanawha/proc/process.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/fs/file.h>
#include <kanawha/kmalloc.h>
#include <kanawha/assert.h>
#include <kanawha/fs/node.h>
#include <kanawha/uapi/file.h>

int
syscall_connect(
        fd_t file,
        fd_t __user *connection,
        unsigned long flags)
{
    return -EUNIMPL;
}

