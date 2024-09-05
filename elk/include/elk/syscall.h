#ifndef __KANAWHA__ELK_SYSCALL_H__
#define __KANAWHA__ELK_SYSCALL_H__

#define CONFIG_X64

#include <kanawha/uapi/file.h>
#include <kanawha/uapi/stdint.h>

__attribute__((noreturn))
void
sys_exit(int exitcode);

fd_t
sys_open(
        fd_t parent,
        const char *name,
        unsigned long access_flags,
        unsigned long mode_flags);

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

#endif
