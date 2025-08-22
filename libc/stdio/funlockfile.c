
#include <elk-libc-internal/__sFILE.h>
#include <stdio.h>
#include <unistd.h>
#include <semaphore.h>

void funlockfile(FILE *filehandle)
{
    int res = -1;
    while(res != 0) {
        res = sem_wait(&filehandle->owner_sem);
    }

    filehandle->owner_pid = -1;

    sem_post(&filehandle->owner_sem);
}

