
#include <errno.h>
#include <semaphore.h>

int
sem_trywait(sem_t *sem)
{
    __elk_libc_sem_lock(sem);
    if(sem->value <= 0)
    {
        __elk_libc_sem_unlock(sem);
        return -EAGAIN;
    }
    sem->value--;
    __elk_libc_sem_unlock(sem);
    return 0;
}
