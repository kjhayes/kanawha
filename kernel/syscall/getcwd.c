
#include <kanawha/syscall.h>
#include <kanawha/string.h>

int
syscall_getcwd(
        struct process *process,
        char __user *buffer,
        size_t buflen)
{
    // TODO: This is a stub.

    int res;

    const char *to_write = ".";

    size_t len = strlen(to_write);
    len = len > buflen ? buflen : len;

    res = process_write_usermem(
            process,
            buffer,
            (void*)to_write,
            len);
    if(res) {
        return res;
    }

    return 0;
}

