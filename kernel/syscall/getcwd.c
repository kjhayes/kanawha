
#include <kanawha/syscall.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>

int
syscall_getcwd(
        struct process *process,
        char __user *buffer,
        size_t buflen)
{
    int res;

    struct fs_path *cwd = process->working_directory;

//    if(process->working_directory == process->root_directory) {
//        // Special Case
//        const char *root_str = "/";
//        size_t to_copy = strlen(root_str) + 1;
//        if(buflen < to_copy) {
//            to_copy = buflen;
//        }
//
//        res = process_write_usermem(
//                process,
//                buffer,
//                (void*)root_str,
//                to_copy);
//        if(res) {
//            return res;
//        }
//
//        return 0;
//    }

    if(!KERNEL_ADDR(cwd)) {
        eprintk("PID(%ld) syscall_getcwd: process has no working directory! (should not be possible)\n",
                (sl_t)process->id);
        return -EINVAL;
    }

    size_t len = 0;
    do {
        char *name;
        if(cwd == process->root_directory) {
            name = "/";
        }
        else if(cwd->name == NULL) {
            name = "";
        } else {
            name = cwd->name;
        }
        len += strlen(name);
        if(*name != '/') {
            len += 1;
        }
        cwd = cwd->parent;

        if(cwd == process->working_directory) {
            // Something is very wrong
            eprintk("PID(%ld) syscall_getcwd: Found loop traversing from working directory to root directory!\n",
                    (sl_t)process->id);
            return -EINVAL;
        }
    } while(cwd && cwd != process->root_directory);

    char *path_buffer = kmalloc(len + 1);
    if(path_buffer == NULL) {
        return -ENOMEM;
    }

    {
    cwd = process->working_directory;
    char *iter = path_buffer + len;
    size_t room = 0;
    do {
        char *name;
        if(cwd == process->root_directory) {
            name = "/";
        }
        else if(cwd->name == NULL) {
            name = "";
        } else {
            name = cwd->name;
        }       
        size_t curlen = strlen(name);
        iter -= curlen;
        room += curlen;
        DEBUG_ASSERT(iter >= path_buffer);

        memcpy(iter, name, curlen > room ? room : curlen);

        if(*name != '/') {
            iter -= 1;
            room += 1;
            DEBUG_ASSERT(iter >= path_buffer);
            *iter = '/';
        }

        cwd = cwd->parent;
        if(cwd == process->working_directory) {
            // Something is very wrong
            eprintk("PID(%ld) syscall_getcwd: Found loop traversing from working directory to root directory!\n",
                    (sl_t)process->id);
            kfree(path_buffer);
            return -EINVAL;
        }
    } while(cwd && cwd != process->root_directory);

    path_buffer[len] = '\0';
    }

    size_t len_to_write = buflen > len+1 ? len+1 : buflen;

    res = process_write_usermem(
            process,
            buffer,
            (void*)path_buffer,
            len_to_write);
    if(res) {
        kfree(path_buffer);
        return res;
    }

    kfree(path_buffer);

    return 0;
}

