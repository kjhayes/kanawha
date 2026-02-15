
#include <kanawha/sys-wrappers.h>
#include <kanawha/file.h>
#include <kanawha/errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

int
__elk_doopen(
        const char *pathname,
        int flags,
	va_list args,
	fd_t *dir_fd)
{
    int res;

    mode_t mode = 0;

    if(flags & O_CREAT)
    {
        mode = va_arg(args, mode_t);
    }

    // TODO Handle the file mode

    unsigned long access_flags = 0;
    unsigned long mode_flags = 0;

    switch(flags & (O_RDONLY | O_WRONLY | O_RDWR)) {
        case O_RDONLY:
            access_flags |= FILE_PERM_READ;
            break;
        case O_WRONLY:
            access_flags |= FILE_PERM_WRITE;
            break;
        case O_RDWR:
            access_flags |= FILE_PERM_READ;
            access_flags |= FILE_PERM_WRITE;
            break;
        default:
            errno = -EINVAL;
            return -1;
    }

    if(flags & O_NONBLOCK) {
        mode_flags |= FILE_MODE_NON_BLOCK;
    }
    if(flags & O_TRUNC) {
        mode_flags |= FILE_MODE_OPEN_TRUNC;
    }

    if(flags & O_EXEC) {
        access_flags |= FILE_PERM_EXEC;
    }

    mode_flags |= FILE_MODE_WRITE_EXTEND;

    fd_t file_fd;
    if(dir_fd != NULL) {
	file_fd = *dir_fd;
	mode_flags |= FILE_MODE_OPEN_RELATIVE;
    }

    res = kanawha_sys_open(
            pathname,
            access_flags,
            mode_flags,
            &file_fd);
    if(res == 0) {
        return file_fd;
    } else if(res != -ENXIO) {
        errno = res;
        return -1;
    }

    // We need to make the file
    if(flags & O_CREAT) {
        char *pathname_dup = strdup(pathname);
        char *directory = pathname_dup;
        char *slash = strrchr(directory, '/');
        const char *new_file_name;
        if(slash == NULL) {
            new_file_name = directory;
            directory = "";
        } else {
            *slash = '\0';
            new_file_name = slash + 1;
        }

        fd_t dir_fd;
        res = kanawha_sys_open(
                directory,
                FILE_PERM_READ|FILE_PERM_WRITE,
                0,
                &dir_fd);
        if(res) {
            free(pathname_dup);
            errno = res;
            return -1;
        }
        unsigned long mkfile_flags = 0;
        res = kanawha_sys_mkfile(
                dir_fd,
                new_file_name,
                mkfile_flags);
        free(pathname_dup);
        if(res) {
            errno = res;
            return -1;
        }

        res = kanawha_sys_flush(dir_fd, 0);
        if(res) {
            errno = res;
            return -1;
        }

        res = kanawha_sys_close(dir_fd);
        if(res) {
            errno = res;
            return -1;
        }
    }

    if(dir_fd != NULL) {
	file_fd = *dir_fd;
	mode_flags |= FILE_MODE_OPEN_RELATIVE;
    }
    res = kanawha_sys_open(
            pathname,
            access_flags,
            mode_flags,
            &file_fd);
    if(res) {
        errno = res;
        return -1;
    }

    return file_fd;
}
