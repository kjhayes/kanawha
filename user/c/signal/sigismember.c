
#include <signal.h>
#include <stddef.h>
#include <errno.h>

int
sigismember(const sigset_t *set, int signum)
{
    if(signum >= __ELK_LIBC_SIGSET_SIGNAL_COUNT) {
        errno = -ERANGE;
        return -1;
    }

    size_t long_index = signum / (sizeof(unsigned long) * 8);
    size_t bit_index = signum % (sizeof(unsigned long) * 8);

    return !!(set->data[long_index] & (1ULL<<bit_index));
}

