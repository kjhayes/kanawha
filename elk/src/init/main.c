
#include <elk/syscall.h>
#include <elk/init/path.h>
#include <kanawha/uapi/spawn.h>

static fd_t stdout = NULL_FD;
static fd_t stdin = NULL_FD;

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
run_thread(
        int(*thread_f)(void),
        pid_t *pid)
{
    extern void _thread_start(void);

    int res;

    pid_t child_pid;
    res = sys_spawn(
            _thread_start,
            (void*)thread_f,
            SPAWN_MMAP_SHARED|SPAWN_ENV_SHARED|SPAWN_FILES_SHARED,
            &child_pid);

    if(res) {
        puts("sys_spawn Failed!\n");
        sys_exit(-res);
    }

    *pid = child_pid;

    return res;
}

int child_thread(void)
{
    puts("child_thread\n");
    return 0;
}

int main(int argc, const char **argv)
{
    int res;

    stdin =
        open_path(
                "char:COM0",
                FILE_PERM_READ,
                0);

    if(stdin == NULL_FD) {
        sys_exit(1);
    }

    stdout =
        open_path(
                "char:vga-serial",
                FILE_PERM_WRITE,
                0);

    if(stdout == NULL_FD) {
        sys_close(stdin);
        sys_exit(1);
    }

    puts("Hello From Userspace!!!\n");

    pid_t child_pid;

    for(size_t i = 0; i < 15; i++) {
        res = run_thread(child_thread, &child_pid);
        if(res) {
            puts("run_thread failed!\n");
            sys_exit(-res);
        }
        int exitcode;
        while(sys_reap(child_pid, 0, &exitcode));
    }

    for(int i = 0; i < argc; i++) {
        puts("ARG: \"");
        puts(argv[i]);
        puts("\"\n");
    }

    int reading = 1;
    while(reading) {
        char c;
        ssize_t amt = sys_read(stdin, &c, 1);
        if(amt < 0) {
            puts("sys_read returned an error!\n");
            sys_exit(-amt);
        }
        if(amt == 1) {
            if(c == '\r') {
                c = '\n';
            }
            sys_write(stdout, &c, 1);
        }
        if(c == 'X') {
            reading = 0;
        }
    }

    puts("\nDetected (X), stopping\n");

    sys_close(stdout);
    sys_close(stdin);

    return 0;
}

