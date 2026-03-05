
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/syscall.h>

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

    size_t len = 0;
    res = fs_path_get(cwd);
    if(res)
    {
        return res;
    }
    do
    {
        DEBUG_ASSERT(KERNEL_ADDR(cwd));

        const char *name = fs_path_get_name(cwd);
        if(cwd == process->root_directory)
        {
            name = "";
        }
        else if(name == NULL)
        {
            name = "";
        }
        len += strlen(name);

        if(*name != '/')
        {
            len += 1;
        }

        if(cwd == process->root_directory)
        {
            fs_path_put(cwd);
            break;
        }

        struct fs_path *parent = fs_path_get_parent(cwd);
        fs_path_put(cwd);
        cwd = parent;

        if(cwd == process->working_directory)
        {
            // Something is very wrong
            eprintk("PID(%ld) syscall_getcwd: Found loop traversing from "
                    "working directory to root directory!\n",
                    (sl_t)process->id);
            fs_path_put(cwd);
            return -EINVAL;
        }
    } while(1);

    char *path_buffer = kmalloc(len + 1, KM_KERNEL);
    if(path_buffer == NULL)
    {
        return -ENOMEM;
    }

    {
        cwd = process->working_directory;
        char *iter = path_buffer + len;
        size_t room = 0;
        res = fs_path_get(cwd);
        if(res)
        {
            kfree(path_buffer);
            return res;
        }
        do
        {
            const char *name = fs_path_get_name(cwd);
            if(cwd == process->root_directory)
            {
                name = "/";
            }
            else if(name == NULL)
            {
                name = "";
            }
            size_t curlen = strlen(name);
            iter -= curlen;
            room += curlen;
            DEBUG_ASSERT(iter >= path_buffer);

            memcpy(iter, name, curlen > room ? room : curlen);

            if(*name != '/')
            {
                iter -= 1;
                room += 1;
                DEBUG_ASSERT(iter >= path_buffer);
                *iter = '/';
            }

            if(cwd == process->root_directory)
            {
                fs_path_put(cwd);
                break;
            }

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
                kfree(path_buffer);
                fs_path_put(cwd);
                return -EINVAL;
            }
        } while(1);

        path_buffer[len] = '\0';
    }

    size_t len_to_write = buflen > len + 1 ? len + 1 : buflen;

    res = process_write_usermem(process,
                                buffer,
                                (void *)path_buffer,
                                len_to_write);
    if(res)
    {
        kfree(path_buffer);
        return res;
    }

    kfree(path_buffer);

    return 0;
}
