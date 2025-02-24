
#include <sys/wait.h>
#include <kanawha/process.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/errno.h>

pid_t
waitpid(
        pid_t pid,
        int *status_loc,
        int options)
{
    int res;

    unsigned long reap_flags = 0;
    if(options & WNOHANG) {
        reap_flags |= REAP_NON_BLOCKING;
    }

    if(pid <= 0) {
        reap_flags |= REAP_ANY;
    }

    int child_status;
    pid_t child_pid = pid;

    res = kanawha_sys_reap(
            reap_flags,
            &child_pid,
            &child_status);
    if(res) {
        if(res == -EWOULDBLOCK) {
            return 0;
        }
        // TODO set errno
        return -1;
    }

    // We did it!
    if(status_loc != NULL) {
        *status_loc = child_status;
    }

    return child_pid;
}

