
#include <kanawha/process.h>
#include <kanawha/file.h>
#include <kanawha/assert.h>
#include <kanawha/vmem.h>
#include <kanawha/module.h>

#define SYSCALL_INSMOD_MAX_NAMELEN 128

int
syscall_insmod(
        struct process *process,
        fd_t mod_fd,
        const char __user *modname,
        unsigned long flags)
{
    int res;

    size_t namelen;
    res = process_strlen_usermem(
            process,
            modname,
            SYSCALL_INSMOD_MAX_NAMELEN+1,
            &namelen);
    if(res) {
        eprintk("PID(%ld) syscall_insmod: could not get namelen! (err=%s)\n",
                process->id, errnostr(res));
        return res;
    }
    if(namelen <= 0) {
        eprintk("PID(%ld) syscall_insmod: name length cannot be <= 0! len=%llu\n",
                (sl_t)process->id,
                (ull_t)namelen);
        return -EINVAL;
    }
    if(namelen > SYSCALL_INSMOD_MAX_NAMELEN) {
        eprintk("PID(%ld) syscall_insmod: name is too long! len=%llu, (>%llu)\n",
                (sl_t)process->id,
                (ull_t)namelen,
                (ull_t)SYSCALL_INSMOD_MAX_NAMELEN);
        return -EINVAL;
    }

    char namebuf[namelen + 1];
    res = process_read_usermem(
            process,
            (void*)namebuf,
            (void __user *)modname,
            namelen);
    if(res) {
        eprintk("syscall_insmod: failed to read file name! process_read_usermem(%p) -> %s\n",
                modname, errnostr(res));
        return res;
    }

    namebuf[namelen] = '\0';

    struct file *file = file_table_get_file(
            process->file_table,
            process,
            mod_fd);
    if(file == NULL) {
        eprintk("PID(%ld) syscall_insmod: file descriptor(%ld) does not exist!\n",
                process->id,
                mod_fd);
        return res;
    }

    printk("insmod: %s %s\n",
            file->path->name,
            namebuf);

    struct module *mod = load_module(
            file->path->fs_node,
            namebuf,
            0);
    if(mod == NULL) {
        return -EINVAL;
    }

    return 0;
}

int
syscall_rmmod(
        struct process *process,
        const char __user *modname,
        unsigned long flags)
{
    int res;

    size_t namelen;
    res = process_strlen_usermem(
            process,
            modname,
            SYSCALL_INSMOD_MAX_NAMELEN+1,
            &namelen);
    if(res) {
        eprintk("PID(%ld) syscall_rmmod: could not get namelen! (err=%s)\n",
                process->id, errnostr(res));
        return res;
    }
    if(namelen <= 0) {
        eprintk("PID(%ld) syscall_rmmod: name length cannot be <= 0! len=%llu\n",
                (sl_t)process->id,
                (ull_t)namelen);
        return -EINVAL;
    }
    if(namelen > SYSCALL_INSMOD_MAX_NAMELEN) {
        eprintk("PID(%ld) syscall_rmmod: name is too long! len=%llu, (>%llu)\n",
                (sl_t)process->id,
                (ull_t)namelen,
                (ull_t)SYSCALL_INSMOD_MAX_NAMELEN);
        return -EINVAL;
    }

    char namebuf[namelen + 1];
    res = process_read_usermem(
            process,
            (void*)namebuf,
            (void __user *)modname,
            namelen);
    if(res) {
        eprintk("PID(%ld) syscall_rmmod: failed to read file name! process_read_usermem(%p) -> %s\n",
                process->id, modname, errnostr(res));
        return res;
    }

    namebuf[namelen] = '\0';

    printk("rmmod(%s)\n", namebuf);
    struct module *mod = module_get(namebuf);
    if(mod == NULL) {
        return -ENXIO;
    }
    module_put(mod);

    printk("unload(%s)\n", namebuf);
    // Does a put on the module regardless of success
    return unload_module(mod);
}

