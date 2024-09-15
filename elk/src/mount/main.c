
#include <elk/syscall.h>
#include <kanawha/uapi/mount.h>
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

int main(int argc, const char **argv) {
    int res;

    res = stdio_setup(
        "/chr/COM0",
        "/chr/COM0");
    if(res) {
        return res;
    }

    if(argc < 4) {
        puts("mount: Too Few Arguments\n");
        puts("Usage: mount [SOURCE] [DIR] [MOUNTPOINT] [TYPE] {SPECIAL}\n");
        return -EINVAL;
    }

    unsigned long flags = MOUNT_FILE;

    if(argc >= 5) {
        flags = MOUNT_SPECIAL;
    }

    const char *source   = argv[0];
    const char *dir_path = argv[1];
    const char *mnt_pnt  = argv[2];
    const char *fs_type  = argv[3];

    fd_t dir;
    res = sys_open(
            dir_path,
            0,
            0,
            &dir);
    if(res) {
        puts("mount: Failed to open directory \"");
        puts(dir_path);
        puts("\"\n");
        return res;
    }

    res = sys_mount(
            source,
            dir,
            mnt_pnt,
            fs_type,
            flags);
    if(res) {
        puts("mount: mount syscall failed!\n");
        return res;
    }

    return 0;
}

