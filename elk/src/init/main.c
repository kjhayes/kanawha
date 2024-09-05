
#include <elk/syscall.h>
#include <elk/init/path.h>

static unsigned long
strlen(const char *str)
{
    unsigned long len = 0;
    while(*str) {
        len++;
        str++;
    }
    return len;
}

static int
write_str(
        fd_t file,
        const char *str)
{
    int res;
    res = sys_write(file,
          (void*)str,
          strlen(str));
    if(res) {
        return res;
    }
    return 0;
}

int main(int argc, const char **argv)
{
    int res;

    fd_t stdin =
        open_path(
                "char:COM0",
                FILE_PERM_READ,
                0);

    if(stdin == NULL_FD) {
        sys_exit(1);
    }

    fd_t stdout =
        open_path(
                "char:vga-serial",
                FILE_PERM_WRITE,
                0);

    if(stdout == NULL_FD) {
        sys_close(stdin);
        sys_exit(1);
    }

    write_str(stdout, "Hello From Userspace!!!\n");

    for(int i = 0; i < argc; i++) {
        write_str(stdout, "ARG: \"");
        write_str(stdout, argv[i]);
        write_str(stdout, "\"\n");
    }

    int reading = 1;
    while(reading) {
        char c;
        ssize_t amt = sys_read(stdin, &c, 1);
        if(amt == 1) {
            sys_write(stdout, &c, 1);
        }
        if(c == 'X') {
            reading = 0;
        }
    }

    write_str(stdout, "\nDetected (X), stopping\n");

    sys_close(stdout);
    sys_close(stdin);

    return 0;
}

