
#include <kanawha/uapi/mount.h>
#include <kanawha/process.h>
#include <kanawha/syscall.h>
#include <kanawha/kmalloc.h>
#include <kanawha/fs/type.h>
#include <kanawha/fs/path.h>

#define MOUNT_MAX_SRC_LEN 256
#define MOUNT_MAX_DST_LEN 256
#define MOUNT_MAX_FS_TYPE_LEN 32

int
syscall_mount(
        struct process *process,
        const char __user *src,
        fd_t dst_dir,
        const char __user *dst_name,
        const char __user *fs_type,
        unsigned long flags)
{
    int res;

    // Get the FS type
    struct fs_type *type = NULL;
    {
      size_t fs_type_strlen;
      res = process_strlen_usermem(
              process,
              fs_type,
              MOUNT_MAX_FS_TYPE_LEN,
              &fs_type_strlen);
      if(res) {
          eprintk("PID(%ld) syscall_mount: Failed to get fs_type strlen (err=%s)\n",
                  (sl_t)process->id, errnostr(res));
          return res;
      }
      char *fs_type_buf = kmalloc(fs_type_strlen+1);
      if(fs_type_buf == NULL) {
          return -ENOMEM;
      }
      fs_type_buf[fs_type_strlen] = '\0';

      res = process_read_usermem(
              process,
              fs_type_buf,
              (void __user*)fs_type,
              fs_type_strlen);
      if(res) {
          kfree(fs_type_buf);
          eprintk("PID(%ld) syscall_mount: Failed to read fs_type string (err=%s)\n",
                  (sl_t)process->id, errnostr(res));
          return -ENOMEM;
      }

      type = fs_type_find(fs_type_buf);

      if(type == NULL) {
          eprintk("PID(%ld) syscall_mount: Could not find fs type \"%s\"\n",
                (sl_t)process->id, fs_type_buf);
          kfree(fs_type_buf);
          return -ENXIO;
      } else {
          dprintk("PID(%ld) syscall_mount: Found fs_type \"%s\"\n",
                  process->id, fs_type_buf);
      }


      kfree(fs_type_buf);
    }

    // Get the source string
    struct fs_mount *mnt = NULL;

    {
      size_t src_strlen;
      res = process_strlen_usermem(
              process,
              src,
              MOUNT_MAX_DST_LEN,
              &src_strlen);
      if(res) {
          eprintk("PID(%ld) syscall_mount: Failed to get source strlen (err=%s)\n",
                  (sl_t)process->id, errnostr(res));
          return res;
      }
      char *src_buf = kmalloc(src_strlen+1);
      if(src_buf == NULL) {
          return -ENOMEM;
      } 

      res = process_read_usermem(
              process,
              src_buf,
              (void __user *)src,
              src_strlen);
      if(res) {
          kfree(src_buf);
          return res;
      }
      src_buf[src_strlen] = '\0';

      if(flags & MOUNT_SPECIAL) {
          res = fs_type_mount_special(type, src_buf, &mnt);
          if(res) {
              kfree(src_buf);
              eprintk("PID(%ld) syscall_mount: Failed to mount special fs mount (id=%s) (err=%s)\n",
                  (sl_t)process->id, src_buf, errnostr(res));
              return res;
          }
      } else {
          fd_t src_fd;
          res = file_table_open(
                  process->file_table,
                  process,
                  src_buf,
                  FILE_PERM_READ|FILE_PERM_WRITE,
                  0,
                  &src_fd);
          if(res) {
              kfree(src_buf);
              return res;
          }

          struct file *src_desc =
              file_table_get_file(
                      process->file_table,
                      process,
                      src_fd);
          if(src_desc == NULL) {
              kfree(src_buf);
              file_table_close(
                      process->file_table,
                      process,
                      src_fd);
              return -EINVAL;
          }

          res = fs_type_mount_file(
                  type,
                  src_desc->path->fs_node,
                  &mnt);

          file_table_put_file(
                  process->file_table,
                  process,
                  src_desc);
          file_table_close(
                  process->file_table,
                  process,
                  src_fd);

          if(res) {
              eprintk("PID(%ld) syscall_mount: fs_type_mount_file returned %s!\n",
                      process->id, errnostr(res));
              kfree(src_buf);
              return res;
          }
      }

      kfree(src_buf);
    }

    if(mnt == NULL) {
        return -EINVAL;
    }

    // Get the destination file name
    size_t dst_name_strlen;
    res = process_strlen_usermem(
            process,
            dst_name,
            MOUNT_MAX_DST_LEN,
            &dst_name_strlen);
    if(res) {
        return res;
    }
    char *dst_name_buf = kmalloc(dst_name_strlen+1);
    if(dst_name_buf == NULL) {
        return -ENOMEM;
    }

    res = process_read_usermem(
            process,
            dst_name_buf,
            (void __user*)dst_name,
            dst_name_strlen);
    if(res) {
        kfree(dst_name_buf);
        return res;
    }
    dst_name_buf[dst_name_strlen] = '\0';

    struct file *dst_desc =
        file_table_get_file(
                process->file_table,
                process,
                dst_dir);
    if(dst_desc == NULL) {
        kfree(dst_name_buf);
        eprintk("PID(%ld) syscall_mount: Could not find destination directory descriptor!\n",
                (sl_t)process->id);
        return -ENXIO;
    }

    struct fs_path *mnt_point;
    res = fs_path_mount_dir(
            dst_desc->path,
            dst_name_buf,
            mnt,
            &mnt_point);
    if(res) {
        kfree(dst_name_buf);
        file_table_put_file(
                process->file_table,
                process,
                dst_desc);
        return res;
    }

    kfree(dst_name_buf);
    file_table_put_file(
            process->file_table,
            process,
            dst_desc);

    return 0;
}

int
syscall_unmount(
        struct process *process,
        fd_t mntpoint_fd)
{
    return -EUNIMPL;
}

