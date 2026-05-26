
#include <semaphore.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/mwait.h>

int
sem_post(sem_t *sem)
{
    __elk_libc_sem_lock(sem);
    sem->value++;
    if(sem->value > 0 && sem->waiting > 0) {
        typeof(sem->waiting_seq) seq = sem->waiting_seq;
        while (sem->waiting > 0 && sem->waiting_seq == seq) {
            __elk_libc_sem_unlock(sem);
            kanawha_sys_mwake(&sem->value, MWAKE_SINGLE);
            __elk_libc_sem_lock(sem);
        }
    }
    __elk_libc_sem_unlock(sem);
    return 0;
}
