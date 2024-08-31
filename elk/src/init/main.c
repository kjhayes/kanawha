
#include <elk/syscall.h>
#include <elk/init/path.h>

static const char *mount_name = "char";
static const char *serial_name = "vga-serial";

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
    res = write(file,
          0,
          (void*)str,
          strlen(str));
    if(res) {
        return res;
    }
    return 0;
}

int main(void)
{
    int res;

    fd_t serial =
        open_path(
                "char:vga-serial",
                FILE_PERM_WRITE,
                0);

    if(serial == NULL_FD) {
        exit(88);
    }

    write_str(serial, "Hello From Userspace!!!\n");

    close(serial);

    return 0;
}

