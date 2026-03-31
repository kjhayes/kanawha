
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/syscall.h>

#define MAX_CWD_PATHLEN (0x1000)

int
syscall_getcwd(char __user *buffer, size_t buflen)
{
    int res;

    struct process *process = current_process();

    struct fs_path *cwd = process->working_directory;

    if(process->working_directory == process->root_directory)
    {
        // Special Case
        const char *root_str = "/";
        size_t to_copy = strlen(root_str) + 1;
        if(buflen < to_copy)
        {
            to_copy = buflen;
        }

        res = process_write_usermem(process, buffer, (void *)root_str, to_copy);
        if(res)
        {
            return res;
        }

        return 0;
    }

    if(!KERNEL_ADDR(cwd))
    {
        eprintk("PID(%ld) syscall_getcwd: process has no working directory! "
                "(should not be possible)\n",
                (sl_t)process->id);
        return -EINVAL;
    }

    size_t kernel_buflen = buflen > MAX_CWD_PATHLEN ? MAX_CWD_PATHLEN : buflen;
    char *kernel_buffer = kmalloc(kernel_buflen, KM_KERNEL);
    if(kernel_buffer == NULL) {
        return -ENOMEM;
    }

    size_t pathlen = 1; // includes the null terminator
    char *path = kernel_buffer + (kernel_buflen-pathlen);
    *path = '\0'; // Add the final NULL terminator

    {
        cwd = process->working_directory;
        res = fs_path_get(cwd);
        if(res)
        {
            kfree(kernel_buffer);
            return res;
        }
        do
        {
            if(cwd == process->root_directory) {
                fs_path_put(cwd);
                break;
            }

            const char *name = fs_path_get_name(cwd);
            if(name == NULL)
            {
                name = "ERROR_NULL_PATH_NAME";
            }
            size_t curlen = strlen(name);
            path -= (curlen+1);
            pathlen += curlen+1;
            if(pathlen > kernel_buflen) {
                kfree(kernel_buffer);
                return -ENOMEM;
            }

            *path = '/';
            memcpy(path+1, name, curlen);

            struct fs_path *parent = fs_path_get_parent(cwd);
            fs_path_put(cwd);
            cwd = parent;

            if(cwd == process->working_directory)
            {
                // Something is very wrong
                eprintk("PID(%ld) syscall_getcwd: Found loop "
                        "traversing from "
                        "working directory to root directory!\n",
                        (sl_t)process->id);
                kfree(kernel_buffer);
                fs_path_put(cwd);
                return -EINVAL;
            }
        } while(1);
    }

    res = process_write_usermem(process,
                                buffer,
                                (void *)path,
                                pathlen);
    kfree(kernel_buffer);
    if(res)
    {
        return res;
    }

    return 0;
}
