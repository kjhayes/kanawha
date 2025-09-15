#ifndef __KANAWHA__UAPI_SYSCALL_H__
#define __KANAWHA__UAPI_SYSCALL_H__

#ifdef KANAWHA_BUILDING_KERNEL
#include <kanawha/uapi/types.h>
#include <kanawha/uapi/signature.h>
#include <kanawha/uapi/file.h>
#include <kanawha/uapi/process.h>
#else
#include <kanawha/types.h>
#include <kanawha/signature.h>
#include <kanawha/file.h>
#include <kanawha/process.h>
#endif

typedef int syscall_id_t;

#define SYSCALL_SIG_EXIT(RET,ARG,...)\
RET(int)\
ARG(int, exitcode)

#define SYSCALL_SIG_OPEN(RET,ARG,...)\
RET(int)\
ARG(const char __user *, path)\
ARG(unsigned long, access_flags)\
ARG(unsigned long, mode_flags)\
ARG(fd_t __user *, fd)

#define SYSCALL_SIG_CLOSE(RET,ARG,...)\
RET(int)\
ARG(fd_t, file)

#define SYSCALL_SIG_READ(RET,ARG,...)\
RET(ssize_t)\
ARG(fd_t, file)\
ARG(void __user *, dest)\
ARG(size_t, size)

#define SYSCALL_SIG_WRITE(RET,ARG,...)\
RET(ssize_t)\
ARG(fd_t, file)\
ARG(const void __user *, src)\
ARG(size_t, size)

#define SYSCALL_SIG_FLUSH(RET,ARG,...)\
RET(int)\
ARG(fd_t, file)\
ARG(unsigned long, flags)

#define SYSCALL_SIG_SEEK(RET,ARG,...)\
RET(ssize_t)\
ARG(fd_t, file)\
ARG(ssize_t, offset)\
ARG(int, whence)

#define SYSCALL_SIG_MMAP(RET,ARG,...)\
RET(int)\
ARG(fd_t, file)\
ARG(size_t, file_offset)\
ARG(void __user * __user*, where)\
ARG(size_t, size)\
ARG(unsigned long, flags)

#define SYSCALL_SIG_MUNMAP(RET,ARG,...)\
RET(int)\
ARG(void __user *, mapping)

#define SYSCALL_SIG_EXEC(RET,ARG,...)\
RET(int)\
ARG(fd_t, file)\
ARG(unsigned long, exec_flags)

#define SYSCALL_SIG_ENVIRON(RET,ARG,...)\
RET(int)\
ARG(const char __user *, key)\
ARG(char __user *, value)\
ARG(size_t, len)\
ARG(int, operation)

#define SYSCALL_SIG_SPAWN(RET,ARG,...)\
RET(int)\
ARG(void __user *, func)\
ARG(void *, arg)\
ARG(unsigned long, flags)\
ARG(pid_t __user *, child)

#define SYSCALL_SIG_REAP(RET,ARG,...)\
RET(int)\
ARG(unsigned long, flags)\
ARG(pid_t __user *, pid_inout)\
ARG(int __user *, exitcode)

#define SYSCALL_SIG_MOUNT(RET,ARG,...)\
RET(int)\
ARG(const char __user *, source)\
ARG(fd_t, dest_dir)\
ARG(const char __user *, dest_name)\
ARG(const char __user *, fs_type)\
ARG(unsigned long, flags)

#define SYSCALL_SIG_UNMOUNT(RET,ARG,...)\
RET(int)\
ARG(fd_t, mntpoint)

#define SYSCALL_SIG_DIRBEGIN(RET,ARG,...)\
RET(int)\
ARG(fd_t, dir)

#define SYSCALL_SIG_DIRNEXT(RET,ARG,...)\
RET(int)\
ARG(fd_t, dir)

#define SYSCALL_SIG_DIRATTR(RET,ARG,...)\
RET(int)\
ARG(fd_t, dir)\
ARG(int, attr)\
ARG(size_t __user *, value)

#define SYSCALL_SIG_DIRNAME(RET,ARG,...)\
RET(int)\
ARG(fd_t, dir)\
ARG(char __user *, namebuf)\
ARG(size_t, buflen)

#define SYSCALL_SIG_FMOVE(RET,ARG,...)\
RET(int)\
ARG(fd_t, dst)\
ARG(fd_t, src)\
ARG(unsigned long, flags)\
ARG(fd_t __user *, out)\

#define SYSCALL_SIG_FATTR(RET,ARG,...)\
RET(int)\
ARG(fd_t, file)\
ARG(int, attr)\
ARG(size_t __user *, value)\

#define SYSCALL_SIG_FACCESS(RET,ARG,...)\
RET(int)\
ARG(fd_t, file)\
ARG(unsigned long, fields)\
ARG(unsigned long, mode)\

#define SYSCALL_SIG_MKFILE(RET,ARG,...)\
RET(int)\
ARG(fd_t, dir)\
ARG(const char __user *, name)\
ARG(unsigned long, flags)

#define SYSCALL_SIG_MKDIR(RET,ARG,...)\
RET(int)\
ARG(fd_t, dir)\
ARG(const char __user *, name)\
ARG(unsigned long, flags)

#define SYSCALL_SIG_LINK(RET,ARG,...)\
RET(int)\
ARG(fd_t, from)\
ARG(fd_t, dir)\
ARG(const char __user *, link_name)\
ARG(unsigned long, flags)

#define SYSCALL_SIG_SYMLINK(RET,ARG,...)\
RET(int)\
ARG(const char __user *, sym_path)\
ARG(fd_t, dir)\
ARG(const char __user *, link_name)\
ARG(unsigned long, flags)

#define SYSCALL_SIG_UNLINK(RET,ARG,...)\
RET(int)\
ARG(fd_t, dir)\
ARG(const char __user *, name)

#define SYSCALL_SIG_CHROOT(RET,ARG,...)\
RET(int)\
ARG(fd_t, root)

#define SYSCALL_SIG_PIPE(RET,ARG,...)\
RET(int)\
ARG(unsigned long, flags)\
ARG(unsigned long, mode_flags)\
ARG(fd_t __user *, out)

#define SYSCALL_SIG_INSMOD(RET,ARG,...)\
RET(int)\
ARG(fd_t, modfile)\
ARG(const char __user *, modname)\
ARG(unsigned long, flags)

#define SYSCALL_SIG_RMMOD(RET,ARG,...)\
RET(int)\
ARG(const char __user *, modname)\
ARG(unsigned long, flags)

#define SYSCALL_SIG_CHWDIR(RET,ARG,...)\
RET(int)\
ARG(fd_t, dir)

#define SYSCALL_SIG_SLEEP(RET,ARG,...)\
RET(int)\
ARG(size_t, duration)\
ARG(unsigned long, flags)

#define SYSCALL_SIG_TIME(RET,ARG,...)\
RET(ssize_t)\
ARG(unsigned long, flags)

#define SYSCALL_SIG_SIGINFO(RET,ARG,...)\
RET(int)\
ARG(unsigned long, attr)\
ARG(unsigned long __user *, value)

#define SYSCALL_SIG_SIGMOD(RET,ARG,...)\
RET(int)\
ARG(unsigned long, attr)\
ARG(unsigned long, value)

#define SYSCALL_SIG_GETCWD(RET,ARG,...)\
RET(int)\
ARG(char __user *, buffer)\
ARG(size_t, buflen)

#define SYSCALL_SIG_RID(RET,ARG,...)\
RET(int)\
ARG(pid_t, target)\
ARG(unsigned long, flags)\
ARG(id_t __user *, id_out)\

#define SYSCALL_SIG_WID(RET,ARG,...)\
RET(int)\
ARG(pid_t, target)\
ARG(unsigned long, flags)\
ARG(id_t, id)\

#define SYSCALL_SIG_RESIZE(RET,ARG,...)\
RET(int)\
ARG(fd_t, file)\
ARG(size_t, size)\
ARG(unsigned long, flags)\

#define SYSCALL_SIG_POLL(RET,ARG,...)\
RET(int)\
ARG(fd_t, file)\
ARG(unsigned long, watch)\
ARG(unsigned long __user *, triggered)\

#define SYSCALL_SIG_SIGSEND(RET,ARG,...)\
RET(int)\
ARG(pid_t, target)\
ARG(int, signal)\
ARG(unsigned long, flags)\

#define SYSCALL_SIG_PRGET(RET,ARG,...)\
RET(int)\
ARG(unsigned long, type)\
ARG(long, field)\
ARG(unsigned long __user *, value)

#define SYSCALL_SIG_PRSET(RET,ARG,...)\
RET(int)\
ARG(unsigned long, type)\
ARG(long, field)\
ARG(unsigned long, value)

#define SYSCALL_XLIST(X)\
X(exit,      0,  EXIT,       SYSCALL_SIG_EXIT)\
X(open,      1,  OPEN,       SYSCALL_SIG_OPEN)\
X(close,     2,  CLOSE,      SYSCALL_SIG_CLOSE)\
X(read,      3,  READ,       SYSCALL_SIG_READ)\
X(write,     4,  WRITE,      SYSCALL_SIG_WRITE)\
X(seek,      5,  SEEK,       SYSCALL_SIG_SEEK)\
X(flush,     6,  FLUSH,      SYSCALL_SIG_FLUSH)\
X(mmap,      7,  MMAP,       SYSCALL_SIG_MMAP)\
X(munmap,    8,  MUNMAP,     SYSCALL_SIG_MUNMAP)\
X(exec,      9,  EXEC,       SYSCALL_SIG_EXEC)\
X(environ,   10, ENVIRON,    SYSCALL_SIG_ENVIRON)\
X(getcwd,    11, GETCWD,     SYSCALL_SIG_GETCWD)\
X(spawn,     12, SPAWN,      SYSCALL_SIG_SPAWN)\
X(reap,      13, REAP,       SYSCALL_SIG_REAP)\
X(faccess,   14, FACCESS,    SYSCALL_SIG_FACCESS)\
X(mount,     15, MOUNT,      SYSCALL_SIG_MOUNT)\
X(unmount,   16, UNMOUNT,    SYSCALL_SIG_UNMOUNT)\
X(dirbegin,  17, DIRBEGIN,   SYSCALL_SIG_DIRBEGIN)\
X(dirnext,   18, DIRNEXT,    SYSCALL_SIG_DIRNEXT)\
X(dirattr,   19, DIRATTR,    SYSCALL_SIG_DIRATTR)\
X(dirname,   20, DIRNAME,    SYSCALL_SIG_DIRNAME)\
X(fmove,     21, FMOVE,      SYSCALL_SIG_FMOVE)\
X(fattr,     22, FATTR,      SYSCALL_SIG_FATTR)\
X(mkfile,    23, MKFILE,     SYSCALL_SIG_MKFILE)\
X(mkdir,     24, MKDIR,      SYSCALL_SIG_MKDIR)\
X(link,      25, LINK,       SYSCALL_SIG_LINK)\
X(symlink,   26, SYMLINK,    SYSCALL_SIG_SYMLINK)\
X(unlink,    27, UNLINK,     SYSCALL_SIG_UNLINK)\
X(chroot,    28, CHROOT,     SYSCALL_SIG_CHROOT)\
X(pipe,      29, PIPE,       SYSCALL_SIG_PIPE)\
X(insmod,    30, INSMOD,     SYSCALL_SIG_INSMOD)\
X(rmmod,     31, RMMOD,      SYSCALL_SIG_RMMOD)\
X(chwdir,    32, CHWDIR,     SYSCALL_SIG_CHWDIR)\
X(sleep,     33, SLEEP,      SYSCALL_SIG_SLEEP)\
X(time,      34, TIME,       SYSCALL_SIG_TIME)\
X(rid,       37, RID,        SYSCALL_SIG_RID)\
X(wid,       38, WID,        SYSCALL_SIG_WID)\
X(resize,    39, RESIZE,     SYSCALL_SIG_RESIZE)\
X(poll,      40, POLL,       SYSCALL_SIG_POLL)\
X(sigsend,   41, SIGSEND,    SYSCALL_SIG_SIGSEND)\
X(siginfo,   42, SIGINFO,    SYSCALL_SIG_SIGINFO)\
X(sigmod,    43, SIGMOD,     SYSCALL_SIG_SIGMOD)\
X(prget,     44, PRGET,      SYSCALL_SIG_PRGET)\
X(prset,     45, PRSET,      SYSCALL_SIG_PRSET)\

#ifdef KANAWHA_BUILDING_KERNEL

#define DECLARE_SYSCALL_ID_CONSTANTS(__name, __id, __NAME, ...)\
const static syscall_id_t SYSCALL_ID_ ## __NAME = __id;
SYSCALL_XLIST(DECLARE_SYSCALL_ID_CONSTANTS)
#undef DECLARE_SYSCALL_ID_CONSTANTS

#else

#ifdef __user
#undef __user
#endif
#define __user

#define KANAWHA_DECLARE_UAPI_SYSCALL(__name, __ID, __NAME, __SIG)\
    SIG_RETURN_TYPE(__SIG) kanawha_sys_ ## __name (SIG_ARG_DECLS(__SIG));

SYSCALL_XLIST(KANAWHA_DECLARE_UAPI_SYSCALL)

#undef SYSCALL_SIG_EXIT
#undef SYSCALL_SIG_OPEN
#undef SYSCALL_SIG_CLOSE
#undef SYSCALL_SIG_READ
#undef SYSCALL_SIG_WRITE
#undef SYSCALL_SIG_MMAP
#undef SYSCALL_SIG_MUNMAP
#undef SYSCALL_SIG_EXEC
#undef SYSCALL_SIG_ENVIRON
#undef SYSCALL_SIG_GETCWD
#undef SYSCALL_SIG_SPAWN
#undef SYSCALL_SIG_REAP
#undef SYSCALL_SIG_MOUNT
#undef SYSCALL_SIG_UNMOUNT
#undef SYSCALL_SIG_DIRBEGIN
#undef SYSCALL_SIG_DIRNEXT
#undef SYSCALL_SIG_DIRATTR
#undef SYSCALL_SIG_DIRNAME
#undef SYSCALL_SIG_FMOVE
#undef SYSCALL_SIG_FATTR
#undef SYSCALL_SIG_MKFILE
#undef SYSCALL_SIG_MKDIR
#undef SYSCALL_SIG_LINK
#undef SYSCALL_SIG_UNLINK
#undef SYSCALL_SIG_CHROOT
#undef SYSCALL_SIG_PIPE
#undef SYSCALL_SIG_INSMOD
#undef SYSCALL_SIG_RMMOD
#undef SYSCALL_SIG_CHWDIR
#undef SYSCALL_SIG_SLEEP
#undef SYSCALL_SIG_TIME
#undef SYSCALL_SIG_SIGRET
#undef SYSCALL_SIG_SIGROUTE
#undef SYSCALL_SIG_RID
#undef SYSCALL_SIG_WID
#undef SYSCALL_SIG_RESIZE
#undef SYSCALL_SIG_POLL
#undef SYSCALL_SIG_SIGSEND
#undef SYSCALL_XLIST

#endif

#endif
