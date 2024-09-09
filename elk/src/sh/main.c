
#include <elk/syscall.h>
#include <elk/path.h>
#include <kanawha/uapi/spawn.h>
#include <kanawha/uapi/environ.h>
#include <kanawha/uapi/errno.h>

static fd_t stdin = NULL_FD;
static fd_t stdout = NULL_FD;

static int
stdio_setup(const char *stdin_path,
            const char *stdout_path)
{
    stdin = open_path(
            stdin_path,
            FILE_PERM_READ,
            0);
    if(stdin == NULL_FD) {
        return -EINVAL;
    }

    stdout = open_path(
            stdout_path,
            FILE_PERM_WRITE,
            0);
    if(stdout == NULL_FD) {
        return -EINVAL;
    }

    return 0;
}

static int
puts(const char *str)
{
    unsigned long len = 0;
    const char *iter = str;
    while(*iter) {
        len++;
        iter++;
    }
 
    ssize_t res = sys_write(stdout,
          (void*)str,
          len);
    if(res) {
        return res;
    }
    return 0;
}

static char
getchar(void)
{
    while(1) {
        char val;
        ssize_t res = sys_read(
                stdin,
                &val,
                1);

        if(res < 0) {
            sys_exit(res);
        }
        if(res == 0) {
            continue;
        } else {
            return val;
        }
    }
}


char *exec_path = "";
char *argv_data = "";

static size_t
strlen(const char *str)
{
    const char *term = str;
    while(*term != '\0') {
        term++;
    }
    return (size_t)(term - str);
}

static int
strcmp(const char *lhs, const char *rhs)
{
    do {
        unsigned char diff = (unsigned char)*lhs - (unsigned char)*rhs;
        if(diff != 0) {
            return diff;
        }

        if(*lhs == '\0' || *rhs == '\0') {
            break;
        }

        lhs++;
        rhs++;

    } while(1);

    return 0;
}

static int
create_thread(
        int(*thread_f)(void),
        pid_t *pid)
{
    extern void _thread_start(void);

    int res;

    res = sys_spawn(
            _thread_start,
            (void*)thread_f,
            SPAWN_MMAP_SHARED|SPAWN_ENV_CLONE|SPAWN_FILES_SHARED,
            pid);

    if(res) {
        puts("sys_spawn Failed!\n");
        sys_exit(-res);
    }

    return res;
}

static int
do_exec(void)
{
    int res;

    fd_t exec_file =
        open_path(
                exec_path,
                FILE_PERM_EXEC|FILE_PERM_READ,
                0);
    if(exec_file == NULL_FD) {
        puts("Could not find \"");
        puts(exec_path);
        puts("\"\n");
        return -ENXIO;
    }

    res = sys_environ("ARGV", argv_data, strlen(argv_data), ENV_SET);
    if(res) {
        puts("Failed to set environment variable \"ARGV\"\n");
        return res;
    }

    res = sys_exec(exec_file, 0);
    if(res) {
        puts("sys_exec: \"");
        puts(exec_path);
        puts("\" failed!");
        return res;
    }

    // We should never reach here
    puts("Something is very very wrong...\n");
    return 1;
}

static void
do_command(void)
{
    if(strcmp(argv_data,"") == 0) {
        if(strcmp(exec_path,"exit") == 0) {
            sys_exit(0);
        }
        if(strcmp(exec_path,"echo") == 0) {
            puts(argv_data);
        }
    } 

    pid_t pid;
    int res = create_thread(do_exec, &pid);
    if(res) {
        puts("Failed to launch process!\n");
    }

    int exitcode;
    while(sys_reap(pid, 0, &exitcode)) {}
}

int
main(int argc, const char **argv)
{
    int res = stdio_setup(
            "char:COM0",
            "char:COM0");

    int running = 1;

    const size_t buffer_len = 0x2000;
    char input_buffer[buffer_len];


    while(running)
    {
        puts("> ");

        int prev_was_whitespace = 1;
        size_t input_end = 0;
        
        do {
            char c = getchar();

            if(c == '\n' || c == '\r') {
                puts("\n");
                break;
            }

            char put_buf[2];
            put_buf[0] = c;
            put_buf[1] = '\0';
            puts(put_buf);

            switch(c) {
                case ' ':
                case '\t':
                    if(prev_was_whitespace) {
                        continue;
                    } else {
                        c = ' ';
                        prev_was_whitespace = 1;
                        break;
                    }
                default:
                    prev_was_whitespace = 0;
                    break;
            }
            if(input_end < buffer_len-1) {
                input_buffer[input_end] = c;
                input_end++;
            }
        } while(1);

        input_buffer[input_end] = '\0';

        exec_path = &input_buffer[0];
        argv_data = &input_buffer[0];

        while(1) {
            char val = *argv_data;
            if(val == '\0') {
                argv_data = "";
                break;
            }
            else if(val == ' ') {
                *argv_data = '\0';
                argv_data++;
                break;
            }
            argv_data++;
        }

        do_command();
    }
}

