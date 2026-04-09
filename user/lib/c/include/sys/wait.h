#ifndef __ELK_POSIX__WAIT_H__
#define __ELK_POSIX__WAIT_H__

#include <sys/resource.h>
#include <sys/types.h>
#include <signal.h>

#define WNOHANG   (1ULL<<0)
#define WUNTRACED (1ULL<<1)

#define WEXITSTATUS(stat)  (stat & 0xFF)
#define WIFCONTINUED(stat) (0)
#define WIFEXITED(stat)    (1)
#define WIFSIGNALED(stat)  (0)
#define WIFSTOPPED(stat)   (0)
#define WSTOPSIG(stat)     (0)
#define WTERMSIG(stat)     (0)
#define WCOREDUMP(stat)    (0)

#define WEXITED    (1)
#define WSTOPPED   (2)
#define WCONTINUED (3)
#define WNOWAIT    (4)

typedef enum {
    P_ALL = 1,
    P_PID,
    P_GID,
} idtype_t;

pid_t  wait(int *);
int    waitid(idtype_t, id_t, siginfo_t *, int);
pid_t  waitpid(pid_t, int *, int);


pid_t wait3 (int *stat_loc, int options, struct rusage *resource_usage);

#endif
