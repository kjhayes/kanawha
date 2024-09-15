
#include <elk/syscall.h>
#include <kanawha/uapi/dir.h>
#include <kanawha/uapi/file.h>
#include <kanawha/uapi/errno.h>

static fd_t stdin = NULL_FD;
static fd_t stdout = NULL_FD;

static int
stdio_setup(const char *stdin_path,
            const char *stdout_path)
{
    int res;
    res = sys_open(
            stdin_path,
            FILE_PERM_READ,
            0,
            &stdin);
    if(res) {
        return res;
    }

    res = sys_open(
            stdout_path,
            FILE_PERM_WRITE,
            0,
            &stdout);
    if(res) {
        return res;
    }

    return 0;
}

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

int main(int argc, const char **argv)
{
    int res;

    res = stdio_setup(
        "/chr/COM0",
        "/chr/COM0");
    if(res) {
        return res;
    }

    if(argc < 1) {
        puts("ls: Too Few Arguments\n");
        puts("Usage: ls [DIR]\n");
        return -EINVAL;
    }

    fd_t dir;
    res = sys_open(
            argv[0],
            FILE_PERM_READ,
            0,
            &dir);
    if(res) {
        puts("Could not open directory \"");
        puts(argv[0]);
        puts("\"\n");
        return res;
    }

#define NAMELEN 128
    char name_buf[NAMELEN];
    res = sys_dirbegin(dir);
    
    do {
        if(res && res != -ENXIO) {
            sys_close(dir);
            return res;
        }
        if(res == -ENXIO) {
            puts("\n");
            break;
        }

        res = sys_dirname(
                dir,
                name_buf,
                NAMELEN);
        if(res) {
            sys_close(dir);
            return res;
        }

        name_buf[NAMELEN-1] = '\0';

        puts(name_buf);
        puts(" ");

        res = sys_dirnext(dir);
    } while(1);
#undef NAMELEN

    sys_close(dir);
    return 0;
}

