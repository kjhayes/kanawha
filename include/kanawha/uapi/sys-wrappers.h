#ifndef __ELK_KANAWHA__SYS_WRAPPERS_H__
#define __ELK_KANAWHA__SYS_WRAPPERS_H__

#ifndef KANAWHA_BUILDING_KERNEL

#include <kanawha/file.h>
#include <kanawha/mmap.h>
#include <kanawha/process.h>
#include <kanawha/sleep.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

__attribute__((weak)) __attribute__((noreturn)) void
kanawha_sys_exit(int exitcode);

__attribute__((weak)) int
kanawha_sys_open(const char *path,
                 unsigned long access_flags,
                 unsigned long mode_flags,
                 fd_t *fd);

__attribute__((weak)) int
kanawha_sys_close(fd_t file);

__attribute__((weak)) ssize_t
kanawha_sys_read(fd_t file, void *dest, size_t size);

__attribute__((weak)) ssize_t
kanawha_sys_write(fd_t file, const void *src, size_t size);

__attribute__((weak)) ssize_t
kanawha_sys_seek(fd_t file, ssize_t offset, int whence);

__attribute__((weak)) int
kanawha_sys_flush(fd_t file, unsigned long flags);

__attribute__((weak)) int
kanawha_sys_mmap(fd_t file,
                 size_t file_offset,
                 void **where,
                 size_t size,
                 unsigned long flags);

__attribute__((weak)) int
kanawha_sys_munmap(void *mapping);

__attribute__((weak)) int
kanawha_sys_exec(fd_t file, unsigned long exec_flags);

__attribute__((weak)) int
kanawha_sys_getcwd(char *buffer, size_t buflen);

__attribute__((weak)) int
kanawha_sys_environ(const char *key, char *value, size_t len, int opcode);

__attribute__((weak)) int
kanawha_sys_childname(fd_t parent,
                      size_t child_index,
                      char *name_buf,
                      size_t buf_len);

__attribute__((weak)) int
kanawha_sys_spawn(void *func, void *arg, unsigned long flags, pid_t *pid);

__attribute__((weak)) int
kanawha_sys_reap(unsigned long flags, pid_t *child_inout, int *exitcode);

__attribute__((weak)) int
kanawha_sys_mount(const char *source,
                  fd_t dest_dir,
                  const char *dest_name,
                  const char *fs_type,
                  unsigned long flags);

__attribute__((weak)) int
kanawha_sys_dirbegin(fd_t dir);
__attribute__((weak)) int
kanawha_sys_dirnext(fd_t dir);
__attribute__((weak)) int
kanawha_sys_dirattr(fd_t dir, int attr, size_t *value);
__attribute__((weak)) int
kanawha_sys_dirname(fd_t dir, char *buf, size_t buflen);

__attribute__((weak)) int
kanawha_sys_fmove(fd_t f0, fd_t f1, unsigned long flags, fd_t *out);

__attribute__((weak)) int
kanawha_sys_fattr(fd_t file, int attr, size_t *value);

__attribute__((weak)) int
kanawha_sys_faccess(fd_t file, unsigned long fields, unsigned long mode);

__attribute__((weak)) int
kanawha_sys_mkfile(fd_t dir, const char *file_name, unsigned long flags);

__attribute__((weak)) int
kanawha_sys_mkdir(fd_t dir, const char *name, unsigned long flags);

__attribute__((weak)) int
kanawha_sys_link(fd_t from, fd_t dir, const char *name, unsigned long flags);

__attribute__((weak)) int
kanawha_sys_symlink(const char *sympath,
                    fd_t dir,
                    const char *name,
                    unsigned long flags);

__attribute__((weak)) int
kanawha_sys_unlink(fd_t dir, const char *name);

__attribute__((weak)) int
kanawha_sys_chroot(fd_t dir);

__attribute__((weak)) int
kanawha_sys_chwdir(fd_t dir);

__attribute__((weak)) int
kanawha_sys_pipe(unsigned long flags, unsigned long mode_flags, fd_t *out);

__attribute__((weak)) int
kanawha_sys_insmod(fd_t file, const char *modname, unsigned long flags);

__attribute__((weak)) int
kanawha_sys_rmmod(const char *modname, unsigned long flags);

__attribute__((weak)) int
kanawha_sys_sleep(size_t duration, unsigned long flags);

__attribute__((weak)) ssize_t
kanawha_sys_time(unsigned long flags);

__attribute__((weak)) int
kanawha_sys_siginfo(unsigned long attr, unsigned long *value);

__attribute__((weak)) int
kanawha_sys_sigmod(unsigned long attr, unsigned long value);

__attribute__((weak)) int
kanawha_sys_rid(pid_t target, unsigned long flags, id_t *id_out);

__attribute__((weak)) int
kanawha_sys_wid(pid_t target, unsigned long flags, id_t id);

__attribute__((weak)) int
kanawha_sys_resize(fd_t file, size_t size, unsigned long flags);

__attribute__((weak)) int
kanawha_sys_poll(fd_t file, unsigned long watching, unsigned long *triggered);

__attribute__((weak)) int
kanawha_sys_sigsend(pid_t target, int signal, unsigned long flags);

__attribute__((weak)) int
kanawha_sys_prget(unsigned long type,
                  long field,
                  unsigned long *value);

__attribute__((weak)) int
kanawha_sys_prset(unsigned long type,
                  long field,
                  unsigned long value);

__attribute__((weak)) int
kanawha_sys_connect(fd_t file, fd_t *connection, unsigned long flags);

__attribute__((weak)) int
kanawha_sys_accept(fd_t file, fd_t *connection, unsigned long flags);

__attribute__((weak)) int
kanawha_sys_socket(unsigned long flags, unsigned long mode_flags, fd_t *out);

#endif /* KANAWHA_BUILDING_KERNEL */

#endif
