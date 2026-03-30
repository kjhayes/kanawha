
#include <threads.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/spawn.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>

// TODO: We don't clean up old thread's
// stacks...

struct __libc_thrd_creation_state {
    thrd_start_t func;
    void *state;
    uint8_t inited;
} __attribute__((packed));

_Static_assert(offsetof(struct __libc_thrd_creation_state, func) == 0, "");
_Static_assert(offsetof(struct __libc_thrd_creation_state, state) == 8, "");
_Static_assert(offsetof(struct __libc_thrd_creation_state, inited) == 16, "");

extern void _thrd_start(struct __libc_thrd_creation_state * state);

int
thrd_create(thrd_t *thrd, thrd_start_t func, void *state)
{
    int res;

    struct __libc_thrd_creation_state _state = {
        .func = func,
        .state = state,
        .inited = 0,
    };

    pid_t child_pid;
    res = kanawha_sys_spawn(
            _thrd_start,
            &_state,
             SPAWN_ENV_SHARED
            |SPAWN_FILES_SHARED
            |SPAWN_MMAP_SHARED
            ,
            &child_pid);
    if(res) {
        return res;
    }
    thrd->pid = child_pid;

    while(_state.inited == 0) {
        thrd_yield();
    }

    return 0;
}

thrd_t
thrd_current(void)
{
    int res;
    pid_t pid = getpid();
    thrd_t thrd = {
        .pid = pid,
    };
    return thrd;
}

int
thrd_detach(thrd_t thrd)
{
    // TODO
}

int
thrd_equal(thrd_t left, thrd_t right)
{
    return left.pid == right.pid;
}

_Noreturn void
thrd_exit(int exitcode)
{
    kanawha_sys_exit(exitcode);
}

int
thrd_join(thrd_t thrd, int *joined_res)
{
    int res;
    res = waitpid(thrd.pid, joined_res, 0);
    if(res) {
        return thrd_error;
    }
    return thrd_success;
}

int
thrd_sleep(const struct timespec *duration, struct timespec *remaining)
{
    int res;
    res = kanawha_sys_sleep(duration->tv_nsec/1000, SLEEP_DURATION_MSEC);
    if(res) {
        // We have no way of getting how much time actually passed...
        // Just lie and say half the duration happened
        // TODO
        if(remaining) {
            remaining->tv_nsec = duration->tv_nsec / 2;
            remaining->tv_sec = duration->tv_sec / 2;
        }
        errno = res;
        return res;
    }
    if(remaining) {
        *remaining = *duration;
    }
    return 0;
}

void
thrd_yield(void)
{
    // TODO (this is okay for now)
    return;
}

