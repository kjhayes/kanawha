#ifndef __ELK_KANAWHA__SYS_WRAPPERS_H__
#define __ELK_KANAWHA__SYS_WRAPPERS_H__

#undef CONFIG_X64
#define CONFIG_X64

#include "kanawha/uapi/file.h"
#include "kanawha/uapi/process.h"
#include "kanawha/uapi/mmap.h"

__attribute__((noreturn))
void
kanawha_sys_exit(int exitcode);

int
kanawha_sys_open(
        const char *path,
        unsigned long access_flags,
        unsigned long mode_flags,
        fd_t *fd);

int
kanawha_sys_close(
        fd_t file);

ssize_t
kanawha_sys_read(
        fd_t file,
        void *dest,
        size_t size);

ssize_t
kanawha_sys_write(
        fd_t file,
        const void *src,
        size_t size);

ssize_t
kanawha_sys_seek(
        fd_t file,
        ssize_t offset,
        int whence);

int
kanawha_sys_flush(
        fd_t file,
        unsigned long flags);

int
kanawha_sys_mmap(
        fd_t file,
        size_t file_offset,
        void **where,
        size_t size,
        unsigned long flags);

int
kanawha_sys_munmap(
        void *mapping);

int
kanawha_sys_exec(
        fd_t file,
        unsigned long exec_flags);

int
kanawha_sys_environ(
        const char *key,
        char *value,
        size_t len,
        int opcode);

int
kanawha_sys_childname(
        fd_t parent,
        size_t child_index,
        char *name_buf,
        size_t buf_len);

int
kanawha_sys_spawn(
        void *func,
        void *arg,
        unsigned long flags,
        pid_t *pid);

int
kanawha_sys_reap(
        pid_t child,
        unsigned long flags,
        int *exitcode);

pid_t
kanawha_sys_getpid(void);

int
kanawha_sys_mount(
        const char *source,
        fd_t dest_dir,
        const char *dest_name,
        const char *fs_type,
        unsigned long flags);

int
kanawha_sys_dirbegin(
        fd_t dir);
int
kanawha_sys_dirnext(
        fd_t dir);
int
kanawha_sys_dirattr(
        fd_t dir,
        int attr,
        size_t *value);
int
kanawha_sys_dirname(
        fd_t dir,
        char *buf,
        size_t buflen);

int
kanawha_sys_fmove(
        fd_t f0,
        fd_t f1,
        unsigned long flags);

int
kanawha_sys_mkfile(
        fd_t dir,
        const char *file_name,
        unsigned long flags);

int
kanawha_sys_mkdir(
        fd_t dir,
        const char *name,
        unsigned long flags);

int
kanawha_sys_link(
        fd_t from,
        fd_t dir,
        const char *name,
        unsigned long flags);

int
kanawha_sys_symlink(
        const char *sympath,
        fd_t dir,
        const char *name,
        unsigned long flags);

int
kanawha_sys_unlink(
        fd_t dir,
        const char *name);

int
kanawha_sys_chroot(fd_t dir);

int
kanawha_sys_chwdir(fd_t dir);

int
kanawha_sys_pipe(
        unsigned long flags,
        fd_t *out);

int
kanawha_sys_insmod(
        fd_t file,
        const char *modname,
        unsigned long flags);

int
kanawha_sys_rmmod(
        const char *modname,
        unsigned long flags);

#endif
