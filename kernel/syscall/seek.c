
#include <kanawha/syscall.h>
#include <kanawha/file.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/node.h>
#include <kanawha/uapi/seek.h>
#include <kanawha/process.h>

ssize_t
syscall_seek(
        struct process *process,
        fd_t file,
        ssize_t offset,
        int whence)
{
    int res;

    int fs_whence;
    switch(whence) {
        case SEEK_CUR:
            fs_whence = FS_FILE_SEEK_CUR;
            break;
        case SEEK_END:
            fs_whence = FS_FILE_SEEK_END;
            break;
        case SEEK_SET:
            fs_whence = FS_FILE_SEEK_SET;
            break;
        default:
            return -EINVAL;
    }
    
    struct file *desc =
        file_table_get_file(process->file_table, process, file);

    if(desc == NULL) {
        return -ENXIO;
    }

    desc->seek_offset =
        direct_file_seek(
                desc,
                offset,
                fs_whence);

    ssize_t ret_offset = desc->seek_offset;
    file_table_put_file(process->file_table, process, desc);
    return ret_offset;
}

