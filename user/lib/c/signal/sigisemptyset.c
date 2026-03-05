
#include <signal.h>
#include <stddef.h>

int
sigisemptyset(sigset_t *set)
{
    for(size_t i = 0; i < __ELK_LIBC_SIGSET_DATA_LONGS; i++)
    {
        if(set->data[i] != 0)
        {
            return 0;
        }
    }
    return 1;
}
