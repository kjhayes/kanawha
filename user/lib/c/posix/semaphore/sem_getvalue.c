
#include <semaphore.h>

int
sem_getvalue(sem_t *sem, int *out)
{
    __elk_libc_sem_lock(sem);
    *out = sem->value;
    __elk_libc_sem_unlock(sem);
    return 0;
}
