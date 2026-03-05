
#include <errno.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>

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
    while(1)
    {
        typeof(sem->value) value;
        value = __atomic_fetch_sub(&sem->value, 1, __ATOMIC_SEQ_CST);
        if(value <= 0)
        {
            __atomic_fetch_add(&sem->value, 1, __ATOMIC_SEQ_CST);
            // TODO: yield() of some sort
        }
        else
        {
            return 0;
        }
    }
}
