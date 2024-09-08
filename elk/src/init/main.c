
#include <elk/syscall.h>
#include <elk/init/path.h>
#include <kanawha/uapi/spawn.h>
#include <kanawha/uapi/environ.h>

static fd_t stdout = NULL_FD;

const char *exec_path = NULL;

static int
puts(const char *str)
{
    int res;

    unsigned long len = 0;
    const char *iter = str;
    while(*iter) {
        len++;
        iter++;
    }
 
    res = sys_write(stdout,
          (void*)str,
          len);
    if(res) {
        return res;
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

    pid_t child_pid;
    res = sys_spawn(
            _thread_start,
            (void*)thread_f,
            SPAWN_MMAP_SHARED|SPAWN_ENV_CLONE|SPAWN_FILES_NONE,
            &child_pid);

    if(res) {
        puts("sys_spawn Failed!\n");
        sys_exit(-res);
    }

    *pid = child_pid;

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
    
    fd_t exec_fd =
        open_path(exec_path,
                FILE_PERM_READ|FILE_PERM_EXEC,
                0);

    if(exec_fd == NULL_FD) {
        return 2;
    }

    res = sys_environ("ARGV", NULL, 0, ENV_CLEAR);
    if(res) {
        return res;
    }

    // We're going to be leaking a whole stack here (whoops).
    res = sys_exec(exec_fd, 0);
    if(res) {
        return res;
    }

    return 0;
}

int main(int argc, const char **argv)
{
    int res;

    stdout =
        open_path(
                "char:vga-serial",
                FILE_PERM_WRITE,
                0);

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
        while(sys_reap(child_pid, 0, &exitcode));
        
        puts("Elk Init: Process Exited");
    }

    sys_close(stdout);

    return 0;
}

