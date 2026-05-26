
#include <semaphore.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/mwait.h>

int
sem_destroy(sem_t *sem)
{
    __elk_libc_sem_lock(sem);
    int num_waiting = sem->waiting;
    if(num_waiting) {
        kanawha_sys_mwake(&sem->value, MWAKE_ALL);
    }
    __elk_libc_sem_unlock(sem);
    return 0;
}
