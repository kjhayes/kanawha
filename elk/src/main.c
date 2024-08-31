
#include <elk/syscall.h>

static size_t
strlen(const char *str)
{
    size_t len = 0;
    while(*str) {
        len++;
        str++;
    }
    return len;
}

static const char *mount_name = "char";
static const char *serial_name = "vga-serial";

int main(void)
{
    int res;

    fd_t char_mount =
        open(NULL_FD,
             mount_name,
             strlen(mount_name),
             0,
             0);
    if(char_mount == NULL_FD) {
        exit(1);
    }

    fd_t serial =
        open(char_mount,
             serial_name,
             strlen(serial_name),
             FILE_PERM_WRITE,
             0);
    if(serial == NULL_FD) {
        exit(2);
    }

    const char *msg = "Hello World!\n";
    res = write(serial,
          0,
          (void*)msg,
          strlen(msg));
    if(res) {
        return res;
    }

    return 0;
}

