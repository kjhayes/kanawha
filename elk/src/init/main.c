
#include <elk/syscall.h>
#include <kanawha/uapi/spawn.h>
#include <kanawha/uapi/environ.h>
#include <kanawha/uapi/errno.h>
#include <kanawha/uapi/mount.h>

static fd_t stdout = NULL_FD;

const char *exec_path = NULL;

static int
puts(const char *str)
{
    unsigned long len = 0;
    const char *iter = str;
    while(*iter != '\0') {
        len++;
        iter++;
    }

    ssize_t written = 0;

    while(written < len) {
        ssize_t cur = sys_write(
              stdout,
              (void*)(str + written),
              (len-written));
        if(cur < 0) {
            return cur;
        }
        else if(cur == 0) {
            return -ERANGE;
        } else {
            written += cur;
        }
    }

    return 0;
}

int
run_exec_thread(
        int(*thread_f)(void),
        pid_t *pid)
{
    extern void _thread_start(void);

    int res;

    res = sys_spawn(
            _thread_start,
            (void*)thread_f,
            SPAWN_MMAP_SHARED|SPAWN_ENV_CLONE|SPAWN_FILES_NONE,
            pid);

    if(res) {
        puts("sys_spawn Failed!\n");
        sys_exit(-res);
    }

    return res;
}

int exec_thread(void)
{
    // This thread shares the address space,
    // has a copy of the environment, and no files opened

    int res;

    if(exec_path == NULL) {
        return 1;
    }
    
    fd_t exec_fd;

    res = sys_open(
            exec_path,
            FILE_PERM_READ|FILE_PERM_EXEC,
            0,
            &exec_fd);

    if(res) {
        return res;
    }

    res = sys_environ("ARGV", NULL, 0, ENV_CLEAR);
    if(res) {
        return res;
    }

    // We're going to be leaking a whole stack here (whoops).
    res = sys_exec(exec_fd, 0);
    if(res) {
        sys_exit(res);
    }

    sys_exit(1);
}

int main(int argc, const char **argv)
{
    int res;

    fd_t root;
    res = sys_open(
            "/",
            0,
            0,
            &root);
    if(res) {
        return res;
    }

    res = sys_mount(
            "chardev",
            root,
            "chr",
            "sys",
            MOUNT_SPECIAL);
    if(res) {
        return res;
    }

    res = sys_open(
                "/chr/vga-serial",
                FILE_PERM_WRITE,
                0,
                &stdout);

    if(stdout == NULL_FD) {
        return 1;
    }


    pid_t child_pid;

    if(argc < 1) {
        return 2;
    }

    exec_path = argv[0];

    if(exec_path == NULL) {
        return 3;
    }

    while(1) {
        puts("Elk Init: Launching Process \"");
        puts(exec_path);
        puts("\"\n");

        res = run_exec_thread(exec_thread, &child_pid);
        if(res) {
            puts("run_thread failed!\n");
            sys_exit(-res);
        }
        int exitcode;
        do {
            int reap_ret = sys_reap(child_pid, 0, &exitcode);
            if(reap_ret == 0) {
                break;
            }
            if(reap_ret == -ENXIO) {
                puts("init: child pid does not exist???\n");
            }
        } while(1);
        
        puts("Elk Init: Process Exited!\n");
    }

    sys_close(stdout);

    return 0;
}

