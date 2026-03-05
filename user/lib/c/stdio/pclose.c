
#include <elk-libc-internal/__sFILE.h>
#include <errno.h>
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int
pclose(FILE *file)
{
    int status;
    int options;
    while(1)
    {
        int res = waitpid(file->pfile_pid, &status, options);

        if(res == file->pfile_pid)
        {
            if(WIFEXITED(status) || WIFSIGNALED(status))
            {
                break;
            }
        }
        else
        {
            return -1;
        }
    }

    return 0;
}
