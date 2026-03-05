
#include <errno.h>
#include <signal.h>
#include <stddef.h>

int
sigaddset(sigset_t *set, int signal)
{
    if(signal >= __ELK_LIBC_SIGSET_SIGNAL_COUNT)
    {
        errno = -ERANGE;
        return -1;
    }

    size_t long_index = signal / (sizeof(unsigned long) * 8);
    size_t bit_index = signal % (sizeof(unsigned long) * 8);

    set->data[long_index] |= (1ULL << bit_index);

    return 0;
}
