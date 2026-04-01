
#include <elk-libc-internal/__sFILE.h>
#include <errno.h>
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

FILE *
popen(const char *command, const char *mode)
{
    int res;

    const char *shell_path = getenv("SHELL");
    if(shell_path == NULL)
    {
        errno = -ENXIO;
        return NULL;
    }

    if(strlen(mode) != 1)
    {
        errno = -EINVAL;
        return NULL;
    }

    switch(*mode)
    {
    case 'r':
    case 'w':
        break;
    default:
        errno = -EINVAL;
        return NULL;
    }

    struct __sFILE *file = malloc(sizeof(*file));
    if(file == NULL)
    {
        errno = -ENOMEM;
        return NULL;
    }

    __elk_libc_internal__init_sFILE(file);

    fd_t child_rp, parent_wp;
    res = kanawha_sys_pipe(0, 0, &child_rp, &parent_wp);
    if(res)
    {
        free(file);
        errno = res;
        return NULL;
    }

    fd_t parent_rp, child_wp;
    res = kanawha_sys_pipe(0, 0, &parent_rp, &child_wp);
    if(res)
    {
        close(child_rp);
        close(parent_wp);
        free(file);
        errno = res;
        return NULL;
    }

    pid_t pid = fork();
    if(pid == 0)
    {
        // We are the child
        if(*mode == 'r')
        {
            dup2(child_wp, stdout->__fd);
        }
        else
        { // mode == 'w'
            dup2(child_rp, stdin->__fd);
        }

        execl(shell_path, "sh", "-c", command, (char *)0);

        abort();
    }
    else
    {
        // We are the parent
        file->pfile_pid = pid;
        // TODO: This is wrong...
        file->__fd = parent_rp;
        return (FILE *)file;
    }
}
