#ifndef __KANAWHA__ELK_SYSCALL_H__
#define __KANAWHA__ELK_SYSCALL_H__

#define CONFIG_X64

#include <kanawha/uapi/file.h>
#include <kanawha/uapi/stdint.h>
#include <kanawha/uapi/process.h>

__attribute__((noreturn))
void
sys_exit(int exitcode);

int
sys_open(
        const char *path,
        unsigned long access_flags,
        unsigned long mode_flags,
        fd_t *fd);

int
sys_close(
        fd_t file);

ssize_t
sys_read(
        fd_t file,
        void *dest,
        size_t size);

ssize_t
sys_write(
        fd_t file,
        void *src,
        size_t size);

ssize_t
sys_seek(
        fd_t file,
        ssize_t offset,
        int whence);

int
sys_attr(
        fd_t file,
        int attr,
        size_t *value);

int
sys_mmap(
        fd_t file,
        size_t file_offset,
        void *where,
        size_t size,
        unsigned long prot_flags,
        unsigned long mmap_flags);

int
sys_munmap(
        void *mapping);

int
sys_exec(
        fd_t file,
        unsigned long exec_flags);

int
sys_environ(
        const char *key,
        char *value,
        size_t len,
        int opcode);

int
sys_childname(
        fd_t parent,
        size_t child_index,
        char *name_buf,
        size_t buf_len);

int
sys_spawn(
        void *func,
        void *arg,
        unsigned long flags,
        pid_t *pid);

int
sys_reap(
        pid_t child,
        unsigned long flags,
        int *exitcode);

pid_t
sys_getpid(void);

int
sys_mount(
        const char *source,
        fd_t dest_dir,
        const char *dest_name,
        const char *fs_type,
        unsigned long flags);

#endif
