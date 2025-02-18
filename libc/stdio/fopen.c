
#include <elk-libc-internal/FILE.h>
#include <elk-libc-internal/__sFILE.h>

#include <kanawha/sys-wrappers.h>
#include <kanawha/file.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#undef fopen
FILE *fopen(
        const char * restrict path,
        const char * restrict mode)
{
    struct __sFILE *file = malloc(sizeof(struct __sFILE));
    if(file == NULL) {
        return NULL;
    }

    unsigned long access_flags = 0;
    unsigned long mode_flags = 0;

    int can_create = 0;
    int truncate = 0;
    int append = 0;

    if(strchr(mode, 'r') != NULL) {
        access_flags |= FILE_PERM_READ;
    }

    if(strchr(mode, 'w') != NULL) {
        can_create = 1;
        truncate = 1;
        access_flags |= FILE_PERM_WRITE;
    }

    if(strchr(mode, 'a') != NULL) {
        can_create = 1;
        append = 1;
        access_flags |= FILE_PERM_WRITE;
    }

    if(strchr(mode, '+') != NULL) {
        access_flags |= FILE_PERM_READ;
        access_flags |= FILE_PERM_WRITE;
    }

    if(truncate) {
        mode_flags |= FILE_MODE_OPEN_TRUNC;
    }

    int res = kanawha_sys_open(
            path,
            access_flags,
            mode_flags,
            &file->__fd);
    if(res == -ENXIO && can_create) {

        size_t pathlen = strlen(path);
        char *path_copy = malloc(pathlen+1);
        if(path_copy == NULL) {
            free(file);
            return NULL;
        }
        strncpy(path_copy, path, pathlen);
        path_copy[pathlen] = '\0';

        char *dirpath;
        char *filename = strrchr(path_copy, '/');
        if(filename == NULL) {
            dirpath = "/";
            filename = path_copy;
        } else {
            dirpath = path_copy;
            filename[0] = '\0';
            filename = filename+1;
        }

        fd_t dir;
        res = kanawha_sys_open(
                dirpath,
                FILE_PERM_READ|FILE_PERM_WRITE,
                0,
                &dir);
        if(res) {
            free(path_copy);
            free(file);
            return NULL;
        }

        res = kanawha_sys_mkfile(
                dir,
                filename,
                0);
        if(res) {
            free(path_copy);
            free(file);
            return NULL;
        }
        free(path_copy);

        res = kanawha_sys_open(
            path,
            access_flags,
            mode_flags,
            &file->__fd);
        if(res) {
            free(file);
            return NULL;
        }
    }
    else if(res) {
        free(file);
        return NULL;
    }

    return (FILE*)file;
}

