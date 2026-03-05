
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>
#include <stdio.h>
#include <string.h>

int
main(int argc, const char **argv)
{
    int res;

    if(argc != 2)
    {
        fprintf(stderr, "Usage: %s [path]\n", argv[0]);
        return -1;
    }

    const char *path = argv[1];

    size_t pathlen = strlen(path);
    char path_buf[pathlen + 1];
    memcpy(path_buf, path, pathlen);
    path_buf[pathlen] = '\0';

    char *filename;
    char *dirpath;
    filename = strrchr(path_buf, '/');
    if(filename == NULL)
    {
        filename = path_buf;
        dirpath = "";
    }
    else
    {
        filename[0] = '\0';
        filename++;
        dirpath = path_buf;
    }

    fd_t dir;
    res = kanawha_sys_open(dirpath, 0, 0, &dir);
    if(res)
    {
        fprintf(stderr, "Failed to open parent directory \"%s\"!", dirpath);
        return -1;
    }

    res = kanawha_sys_mkdir(dir, filename, 0);
    if(res)
    {
        fprintf(stderr, "Failed to create directory \"%s\"!\n", path);
        return -1;
    }

    res = kanawha_sys_flush(dir, 0);
    if(res)
    {
        fprintf(stderr, "Failed to flush parent directory!\n");
        return -1;
    }

    res = kanawha_sys_close(dir);
    if(res)
    {
        fprintf(stderr, "Failed to close parent directory!\n");
        return -1;
    }

    return 0;
}
