
#include <signal.h>
#include <string.h>

int sigemptyset(sigset_t *set)
{
    memset(set->data, 0, sizeof(unsigned long) * __ELK_LIBC_SIGSET_DATA_LONGS);
    return 0;
}
