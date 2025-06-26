
#include <signal.h>
#include <stddef.h>

int sigandset(sigset_t *dest, sigset_t *left, sigset_t *right)
{
    for(size_t i = 0; i < __ELK_LIBC_SIGSET_DATA_LONGS; i++) {
        dest->data[i] = left->data[i] & right->data[i];
    }
}

