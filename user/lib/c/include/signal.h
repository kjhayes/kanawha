#ifndef __ELK_LIBC__SIGNAL_H__
#define __ELK_LIBC__SIGNAL_H__

#include <elk-libc-internal/sigevent.h>
#include <elk-libc-internal/timespec.h>
#include <stdint.h>
#include <sys/types.h>

// The spec requires that these do not
// evaluate to any declarable function,
// but there is not a clear way to make that
// promise other than by providing stub functions
// (Which breaks the promise...)
extern void
__elk_signal__default(int);
extern void
__elk_signal__error(int);
extern void
__elk_signal__hold(int);
extern void
__elk_signal__ignore(int);

#define SIG_DFL __elk_signal__default
#define SIG_ERR __elk_signal__error
#define SIG_HOLD __elk_signal__hold
#define SIG_IGN __elk_signal__ignore

typedef volatile uint64_t sig_atomic_t;

#define __ELK_LIBC_SIGSET_DATA_LONGS (1)
#define __ELK_LIBC_SIGSET_SIGNAL_COUNT                                         \
    (__ELK_LIBC_SIGSET_DATA_LONGS * sizeof(unsigned long) * 8)
typedef struct
{
    unsigned long data[__ELK_LIBC_SIGSET_DATA_LONGS];
} sigset_t;

#define SIGABRT (1)
#define SIGALRM (2)
#define SIGBUS (3)
#define SIGCHLD (4)
#define SIGCONT (5)
#define SIGFPE (6)
#define SIGHUP (7)
#define SIGILL (8)
#define SIGINT (9)
#define SIGKILL (10)
#define SIGPIPE (11)
#define SIGQUIT (12)
#define SIGSEGV (13)
#define SIGSTOP (14)
#define SIGTERM (15)
#define SIGTSTP (16)
#define SIGTTIN (17)
#define SIGTTOU (18)
#define SIGUSR1 (19)
#define SIGUSR2 (20)
#define SIGPOLL (21)
#define SIGPROF (22)
#define SIGSYS (23)
#define SIGTRAP (24)
#define SIGURG (25)
#define SIGVTALRM (26)
#define SIGXCPU (27)
#define SIGXFSZ (28)
// Must be one greater than the maximum defined signal
#define NSIG (29)

typedef struct
{
    int si_signo;          // Signal number.
    int si_code;           // Signal code.
    int si_errno;          // If non-zero, an errno value associated with
                           // this signal, as defined in <errno.h>.
    pid_t si_pid;          // Sending process ID.
    uid_t si_uid;          // Real user ID of sending process.
    void *si_addr;         // Address of faulting instruction.
    int si_status;         // Exit value or signal.
    long si_band;          // Band event for SIGPOLL.
    union sigval si_value; // Signal value.
} siginfo_t;

struct sigaction
{
    void (*sa_handler)(int);
    sigset_t sa_mask;
    int sa_flags;
    void (*sa_sigaction)(int, siginfo_t *, void *);
};

typedef struct
{
    void *ss_sp;    // Stack base or pointer.
    size_t ss_size; // Stack size.
    int ss_flags;   // Flags.
} stack_t;

struct sigstack
{
    int ss_onstack; // Non-zero when signal stack is in use.
    void *ss_sp;    // Signal stack pointer.
};

#define SIG_BLOCK (0)
#define SIG_UNBLOCK (1)
#define SIG_SETMASK (2)

#define SA_NOCLDSTOP (1ULL << 0)
#define SA_ONSTACK (1ULL << 1)
#define SA_RESETHAND (1ULL << 2)
#define SA_RESTART (1ULL << 3)
#define SA_SIGINFO (1ULL << 4)
#define SA_NOCLDWAIT (1ULL << 5)
#define SA_NODEFER (1ULL << 6)

#define SS_ONSTACK (1ULL << 0)
#define SS_DISABLE (1ULL << 1)

#define MINSIGSTKSZ (0x1000)
#define SIGSTKSZ (1ULL << 21)

typedef void (*sighandler_t)(int);

void (*bsd_signal(int, sighandler_t))(int);
int
kill(pid_t, int);
int
killpg(pid_t, int);
int
raise(int);
int
sigaction(int, const struct sigaction *restrict, struct sigaction *restrict);
int
sigaddset(sigset_t *, int);
int
sigaltstack(const stack_t *restrict, stack_t *restrict);
int
sigdelset(sigset_t *, int);
int
sigemptyset(sigset_t *);
int
sigfillset(sigset_t *);
int
sighold(int);
int
sigignore(int);
int
siginterrupt(int, int);
int
sigismember(const sigset_t *, int);
sighandler_t
signal(int, sighandler_t);
int
sigpause(int);
int
sigpending(sigset_t *);
int
sigprocmask(int, const sigset_t *restrict, sigset_t *restrict);
int
sigqueue(pid_t, int, const union sigval);
int
sigrelse(int);
void (*sigset(int, void (*)(int)))(int);
int
sigsuspend(const sigset_t *);
int
sigtimedwait(const sigset_t *restrict,
             siginfo_t *restrict,
             const struct timespec *restrict);
int
sigwait(const sigset_t *restrict, int *restrict);
int
sigwaitinfo(const sigset_t *restrict, siginfo_t *restrict);

// Extensions
int
sigisemptyset(sigset_t *);
int
sigorset(sigset_t *dest, sigset_t *left, sigset_t *right);
int
sigandset(sigset_t *dest, sigset_t *left, sigset_t *right);

#endif
