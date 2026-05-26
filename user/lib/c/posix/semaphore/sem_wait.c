
#include <errno.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/mwait.h>

int
sem_wait(sem_t *sem)
{
    if((uintptr_t)sem < 0x1000)
    {
        fprintf(stderr, "Invalid semaphore!\n");
        while(1)
        {
        }
    }

    __elk_libc_sem_lock(sem);
    while(1)
    {
        if(sem->value > 0) {
            sem->value--;
            __elk_libc_sem_unlock(sem);
            return 0;
        } else {
            sem->waiting++;
            sem->waiting_seq++;
            __elk_libc_sem_unlock(sem);
            kanawha_sys_mwait(&sem->value, 0);
            __elk_libc_sem_lock(sem);
            sem->waiting--;
        }
    }
}
