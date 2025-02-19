
#include <elk-libc-internal/exec_path.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/file.h>

int
__elk_libc__exec_path_lookup(
        const char *file_name,
        fd_t *file_out)
{
    int res;
    size_t filenamelen = strlen(file_name);

    char *path = getenv("PATH");
    char *iter = path;

    int searching = 1;
    while(searching) {
        char *dir = iter;
        char *delim = strchr(iter, ';');
        if(*delim == '\0') {
            // Final iteration
            searching = 0;
        } else {
            *delim = '\0';
            iter = delim+1;
        }
        size_t dirlen = strlen(dir);
        // dir + '/' + file_name + '\0'
        size_t buflen = dirlen+1+filenamelen+1;
        char *buffer = malloc(buflen);
        if(buffer == NULL) {
            continue;
        }
        strncpy(buffer, dir, dirlen+1);
        strncpy(buffer + dirlen + 1, file_name, filenamelen+1);
        buffer[dirlen] = '/';
        buffer[buflen-1] = '\0';

        fd_t desc;
        res = kanawha_sys_open(
                buffer,
                FILE_PERM_READ|FILE_PERM_EXEC,
                0,
                &desc);

        free(buffer);

        if(res) {
            continue;
        } else {
            // We found it!
            *file_out = desc;
            return 0;
        }
    }
    return -ENXIO;
}



