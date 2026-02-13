
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/file.h>
#include <elk-libc-internal/__sFILE.h>

int
pclose(FILE *file)
{
    int status;
    int options;
    while(1) {
	int res = waitpid(file->pfile_pid, &status, options);

	if(res == file->pfile_pid) {
	    if(WIFEXITED(status) || WIFSIGNALED(status))
	    {
		break;
	    }
	}
	else {
	    return -1;
	}
    }

    return 0;
}

