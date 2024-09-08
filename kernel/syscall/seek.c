
#include <kanawha/syscall.h>
#include <kanawha/file.h>
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

    struct file_descriptor *desc =
        file_table_get_descriptor(process->file_table, process, file);

    if(desc == NULL) {
        return -ENXIO;
    }

    size_t file_end;

    switch(whence) {
        case SEEK_SET:
          desc->seek_offset = offset;
          break;
        case SEEK_CUR:
          desc->seek_offset += offset;
          break;
        case SEEK_END:
          res = fs_node_attr(
                  desc->node,
                  FS_NODE_ATTR_END_OFFSET,
                  &file_end);
          if(res) {
              file_table_put_descriptor(process->file_table, process, desc);
              return res;
          }
          desc->seek_offset = file_end + offset;
          break;
        default:
          file_table_put_descriptor(process->file_table, process, desc);
          return -EINVAL;
    }

    ssize_t ret_offset = desc->seek_offset;
    file_table_put_descriptor(process->file_table, process, desc);
    return ret_offset;
}

