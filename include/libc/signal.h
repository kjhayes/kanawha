#ifndef __ELK_LIBC__SIGNAL_H__
#define __ELK_LIBC__SIGNAL_H__

#include <sys/types.h>
#include <stdint.h>

extern void __elk_signal__default(int);
extern void __elk_signal__error(int);
extern void __elk_signal__hold(int);
extern void __elk_signal__ignore(int);

#define SIG_DFL  __elk_signal__default
#define SIG_ERR  __elk_signal__error
#define SIG_HOLD __elk_signal__hold
#define SIG_IGN  __elk_signal__ignore

typedef volatile uint64_t sig_atomic_t;
typedef uint64_t sigset_t;

#define SIGABRT   (1)
#define SIGALRM   (2)
#define SIGBUS    (3)
#define SIGCHLD   (4)
#define SIGCONT   (5)
#define SIGFPE    (6)
#define SIGHUP    (7)
#define SIGILL    (8)   
#define SIGINT    (9)
#define SIGKILL   (10)
#define SIGPIPE   (11)
#define SIGQUIT   (12)
#define SIGSEGV   (13)
#define SIGSTOP   (14)
#define SIGTERM   (15)
#define SIGTSTP   (16)
#define SIGTTIN   (17)
#define SIGTTOU   (18)
#define SIGUSR1   (19)
#define SIGUSR2   (20)
#define SIGPOLL   (21)
#define SIGPROF   (22)
#define SIGSYS    (23)
#define SIGTRAP   (24)
#define SIGURG    (25)
#define SIGVTALRM (26)
#define SIGXCPU   (27)
#define SIGXFSZ   (28)

union sigval {
    int    sival_int;    //Integer signal value. 
    void  *sival_ptr;    //Pointer signal value.
};

typedef struct
{
    int           si_signo;  //Signal number. 
    int           si_code;   //Signal code. 
    int           si_errno;  //If non-zero, an errno value associated with 
                             //this signal, as defined in <errno.h>. 
    pid_t         si_pid;    //Sending process ID. 
    uid_t         si_uid;    //Real user ID of sending process. 
    void         *si_addr;   //Address of faulting instruction. 
    int           si_status; //Exit value or signal. 
    long          si_band;   //Band event for SIGPOLL. 
    union sigval  si_value;  //Signal value.
} siginfo_t;

struct sigaction
{
    void (*sa_handler)(int);
    sigset_t sa_mask;
    int      sa_flags;
    void (*sa_sigaction)(int, siginfo_t *, void *);
};

struct sigevent {
    int                    sigev_notify;            //Notification type. 
    int                    sigev_signo;             //Signal number. 
    union sigval           sigev_value;             //Signal value. 
    void(*sigev_notify_function)(union sigval);     //Notification function. 
    //pthread_attr_t *     sigev_notify_attributes;   //Notification attributes.
};

typedef struct {
    void     *ss_sp;       //Stack base or pointer. 
    size_t    ss_size;     //Stack size. 
    int       ss_flags;    //Flags. 
} stack_t;

struct sigstack {
    int       ss_onstack;  //Non-zero when signal stack is in use. 
    void     *ss_sp;       //Signal stack pointer. 
};

void (*bsd_signal(int, void (*)(int)))(int);
int    kill(pid_t, int);
int    killpg(pid_t, int);
int    raise(int);
int    sigaction(int, const struct sigaction *restrict,
           struct sigaction *restrict);
int    sigaddset(sigset_t *, int);
int    sigaltstack(const stack_t *restrict, stack_t *restrict);
int    sigdelset(sigset_t *, int);
int    sigemptyset(sigset_t *);
int    sigfillset(sigset_t *);
int    sighold(int);
int    sigignore(int);
int    siginterrupt(int, int);
int    sigismember(const sigset_t *, int);
void (*signal(int, void (*)(int)))(int);
int    sigpause(int);
int    sigpending(sigset_t *);
int    sigprocmask(int, const sigset_t *restrict, sigset_t *restrict);
int    sigqueue(pid_t, int, const union sigval);
int    sigrelse(int);
void (*sigset(int, void (*)(int)))(int);
int    sigsuspend(const sigset_t *);
int    sigtimedwait(const sigset_t *restrict, siginfo_t *restrict,
           const struct timespec *restrict);
int    sigwait(const sigset_t *restrict, int *restrict);
int    sigwaitinfo(const sigset_t *restrict, siginfo_t *restrict);

#endif
