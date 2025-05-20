#ifndef __ELK_POSIX__UNISTD_H__
#define __ELK_POSIX__UNISTD_H__

#include <sys/types.h>

#ifndef NULL
#define NULL ((void*)0)
#endif

// access() Related Macros
#define R_OK (1ULL<<0)
#define W_OK (1ULL<<1)
#define X_OK (1ULL<<2)
#define F_OK (1ULL<<3)

// SEEK_SET SEEK_END SEEK_CUR
#include <kanawha/file.h>

// lockf Related Macros
#define F_LOCK  (0)
#define F_ULOCK (1)
#define F_TEST  (2)
#define F_TLOCK (3)


#define STDIN_FILENO  (0)
#define STDOUT_FILENO (1)
#define STDERR_FILENO (2)

typedef __INTPTR_TYPE__ intptr_t;

enum {
    _CS_PATH,
    _CS_XBS5_ILP32_OFF32_CFLAGS,
    _CS_XBS5_ILP32_OFF32_LDFLAGS,
    _CS_XBS5_ILP32_OFF32_LIBS,
    _CS_XBS5_ILP32_OFF32_LINTFLAGS,
    _CS_XBS5_ILP32_OFFBIG_CFLAGS,
    _CS_XBS5_ILP32_OFFBIG_LDFLAGS,
    _CS_XBS5_ILP32_OFFBIG_LIBS,
    _CS_XBS5_ILP32_OFFBIG_LINTFLAGS,
    _CS_XBS5_LP64_OFF64_CFLAGS,
    _CS_XBS5_LP64_OFF64_LDFLAGS,
    _CS_XBS5_LP64_OFF64_LIBS,
    _CS_XBS5_LP64_OFF64_LINTFLAGS,
    _CS_XBS5_LPBIG_OFFBIG_CFLAGS,
    _CS_XBS5_LPBIG_OFFBIG_LDFLAGS,
    _CS_XBS5_LPBIG_OFFBIG_LIBS,
    _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS,
};

enum {
    _SC_2_C_BIND,
    _SC_2_C_DEV,
    _SC_2_C_VERSION,
    _SC_2_FORT_DEV,
    _SC_2_FORT_RUN,
    _SC_2_LOCALEDEF,
    _SC_2_SW_DEV,
    _SC_2_UPE,
    _SC_2_VERSION,
    _SC_ARG_MAX,
    _SC_AIO_LISTIO_MAX,
    _SC_AIO_MAX,
    _SC_AIO_PRIO_DELTA_MAX,
    _SC_ASYNCHRONOUS_IO,
    _SC_ATEXIT_MAX,
    _SC_BC_BASE_MAX,
    _SC_BC_DIM_MAX,
    _SC_BC_SCALE_MAX,
    _SC_BC_STRING_MAX,
    _SC_CHILD_MAX,
    _SC_CLK_TCK,
    _SC_COLL_WEIGHTS_MAX,
    _SC_DELAYTIMER_MAX,
    _SC_EXPR_NEST_MAX,
    _SC_FSYNC,
    _SC_GETGR_R_SIZE_MAX,
    _SC_GETPW_R_SIZE_MAX,
    _SC_IOV_MAX,
    _SC_JOB_CONTROL,
    _SC_LINE_MAX,
    _SC_LOGIN_NAME_MAX,
    _SC_MAPPED_FILES,
    _SC_MEMLOCK,
    _SC_MEMLOCK_RANGE,
    _SC_MEMORY_PROTECTION,
    _SC_MESSAGE_PASSING,
    _SC_MQ_OPEN_MAX,
    _SC_MQ_PRIO_MAX,
    _SC_NGROUPS_MAX,
    _SC_OPEN_MAX,
    _SC_PAGESIZE,
    _SC_PAGE_SIZE,
    _SC_PASS_MAX,
    _SC_PRIORITIZED_IO,
    _SC_PRIORITY_SCHEDULING,
    _SC_RE_DUP_MAX,
    _SC_REALTIME_SIGNALS,
    _SC_RTSIG_MAX,
    _SC_SAVED_IDS,
    _SC_SEMAPHORES,
    _SC_SEM_NSEMS_MAX,
    _SC_SEM_VALUE_MAX,
    _SC_SHARED_MEMORY_OBJECTS,
    _SC_SIGQUEUE_MAX,
    _SC_STREAM_MAX,
    _SC_SYNCHRONIZED_IO,
    _SC_THREADS,
    _SC_THREAD_ATTR_STACKADDR,
    _SC_THREAD_ATTR_STACKSIZE,
    _SC_THREAD_DESTRUCTOR_ITERATIONS,
    _SC_THREAD_KEYS_MAX,
    _SC_THREAD_PRIORITY_SCHEDULING,
    _SC_THREAD_PRIO_INHERIT,
    _SC_THREAD_PRIO_PROTECT,
    _SC_THREAD_PROCESS_SHARED,
    _SC_THREAD_SAFE_FUNCTIONS,
    _SC_THREAD_STACK_MIN,
    _SC_THREAD_THREADS_MAX,
    _SC_TIMERS,
    _SC_TIMER_MAX,
    _SC_TTY_NAME_MAX,
    _SC_TZNAME_MAX,
    _SC_VERSION,
    _SC_XOPEN_VERSION,
    _SC_XOPEN_CRYPT,
    _SC_XOPEN_ENH_I18N,
    _SC_XOPEN_SHM,
    _SC_XOPEN_UNIX,
    _SC_XOPEN_XCU_VERSION,
    _SC_XOPEN_LEGACY,
    _SC_XOPEN_REALTIME,
    _SC_XOPEN_REALTIME_THREADS,
    _SC_XBS5_ILP32_OFF32,
    _SC_XBS5_ILP32_OFFBIG,
    _SC_XBS5_LP64_OFF64,
    _SC_XBS5_LPBIG_OFFBIG,
};

int          access(const char *, int);
unsigned int alarm(unsigned int);
int          brk(void *);
int          chdir(const char *);
int          chroot(const char *);
int          chown(const char *, uid_t, gid_t);
int          close(int);
size_t       confstr(int, char *, size_t);
char        *crypt(const char *, const char *);
char        *ctermid(char *);
char        *cuserid(char *s);
int          dup(int);
int          dup2(int, int);
void         encrypt(char[64], int);
int          execl(const char *, const char *, ...);
int          execle(const char *, const char *, ...);
int          execlp(const char *, const char *, ...);
int          execv(const char *, char *const []);
int          execve(const char *, char *const [], char *const []);
int          execvp(const char *, char *const []);
void        _exit(int);
int          fchown(int, uid_t, gid_t);
int          fchdir(int);
int          fdatasync(int);
pid_t        fork(void);
long int     fpathconf(int, int);
int          fsync(int);
int          ftruncate(int, off_t);
char        *getcwd(char *, size_t);
int          getdtablesize(void);
gid_t        getegid(void);
uid_t        geteuid(void);
gid_t        getgid(void);
int          getgroups(int, gid_t []);
long         gethostid(void);
char        *getlogin(void);
int          getlogin_r(char *, size_t);
int          getopt(int, char **, const char *);
int          getpagesize(void);
char        *getpass(const char *);
pid_t        getpgid(pid_t);
pid_t        getpgrp(void);
pid_t        getpid(void);
pid_t        getppid(void);
pid_t        getsid(pid_t);
uid_t        getuid(void);
char        *getwd(char *);
int          isatty(int);
int          lchown(const char *, uid_t, gid_t);
int          link(const char *, const char *);
int          lockf(int, int, off_t);
off_t        lseek(int, off_t, int);
int          nice(int);
long int     pathconf(const char *, int);
int          pause(void);
int          pipe(int [2]);
ssize_t      pread(int, void *, size_t, off_t);
int          pthread_atfork(void (*)(void), void (*)(void),
                 void(*)(void));
ssize_t      pwrite(int, const void *, size_t, off_t);
ssize_t      read(int, void *, size_t);
ssize_t      readlink(const char * restrict, char * restrict, size_t);
int          rmdir(const char *);
void        *sbrk(intptr_t);
int          setegid(gid_t);
int          seteuid(uid_t);
int          setgid(gid_t);
int          setpgid(pid_t, pid_t);
pid_t        setpgrp(void);
int          setregid(gid_t, gid_t);
int          setreuid(uid_t, uid_t);
pid_t        setsid(void);
int          setuid(uid_t);
unsigned int sleep(unsigned int);
void         swab(const void *, void *, ssize_t);
int          symlink(const char *, const char *);
void         sync(void);
long int     sysconf(int);
pid_t        tcgetpgrp(int);
int          tcsetpgrp(int, pid_t);
int          truncate(const char *, off_t);
char        *ttyname(int);
int          ttyname_r(int, char *, size_t);
useconds_t   ualarm(useconds_t, useconds_t);
int          unlink(const char *);
int          usleep(useconds_t);
pid_t        vfork(void);
ssize_t      write(int, const void *, size_t);

extern char **environ;

#endif
