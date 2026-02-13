
#include <signal.h>
#include <string.h>

int sigfillset(sigset_t *set)
{
    memset(set->data, 0xFF, sizeof(unsigned long) * __ELK_LIBC_SIGSET_DATA_LONGS);
    return 0;
}

