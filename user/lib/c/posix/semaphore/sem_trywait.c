
#include <semaphore.h>
#include <errno.h>

int
sem_trywait(sem_t *sem)
{
    typeof(sem->value) value;
    value = __atomic_fetch_sub(&sem->value, 1, __ATOMIC_SEQ_CST);
    if(value <= 0) {
	__atomic_fetch_add(&sem->value, 1, __ATOMIC_SEQ_CST);
	return -EAGAIN;
    }
    return 0;
}
