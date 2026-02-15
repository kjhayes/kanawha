
#include <kanawha/sys-wrappers.h>
#include <kanawha/dir.h>
#include <kanawha/file.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char **argv)
{
    int res;

    const char *dir_path = ".";

    if(argc >= 2) {
        dir_path = argv[1];
    }

    int show_all = 0;

    fd_t dir;
    res = kanawha_sys_open(
            dir_path,
            FILE_PERM_READ,
            0,
            &dir);
    if(res) {
        puts("Could not open directory \"");
        puts(dir_path);
        puts("\"\n");
        return res;
    }

#define NAMELEN 128
    char *name_buf = malloc(NAMELEN);

    res = kanawha_sys_dirbegin(dir);    
    if(res && res != -ENXIO) {
        goto err;
    }
    if(res == -ENXIO) {
        puts("\n");
    }

    while(res == 0) {
        res = kanawha_sys_dirname(
                dir,
                name_buf,
                NAMELEN);
        if(res) {
            goto err;
        }

        name_buf[NAMELEN-1] = '\0';

        if(show_all || name_buf[0] != '.') {
          puts(name_buf);
          puts(" ");
        }

        res = kanawha_sys_dirnext(dir);
        if(res && res != -ENXIO) {
            goto err;
        }
        if(res == -ENXIO) {
            puts("\n");
            break;
        }
    }
#undef NAMELEN

    kanawha_sys_close(dir);
    free(name_buf);
    return 0;

err:
    kanawha_sys_close(dir);
    free(name_buf);
    return res;
}

