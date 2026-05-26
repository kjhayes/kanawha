
#include <elk-libc-internal/__sFILE.h>
#include <stdio.h>
#include <unistd.h>

void
flockfile(FILE *filehandle)
{
    int res;
    int self = getpid();

    while(1)
    {
        while(1)
        {
            res = sem_wait(&filehandle->owner_sem);
            if(res == 0)
            {
                break;
            }
        }
        if(filehandle->owner_pid == self || filehandle->owner_pid == -1)
        {
            filehandle->owner_pid = self;
            sem_post(&filehandle->owner_sem);
            return;
        }

        sem_post(&filehandle->owner_sem);
        // we should yield here
    }
}
