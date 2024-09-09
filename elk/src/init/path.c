
#include <elk/init/path.h>
#include <elk/syscall.h>

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

fd_t
open_path(
        const char *path,
        unsigned long perm_flags,
        unsigned long mode_flags)
{
    unsigned long pathlen = strlen(path);
    char buffer[pathlen+1];
    char *buffer_end = buffer + pathlen + 1;
    buffer[pathlen] = '\0';
    
    int colon_offset = -1;

    int total_num_opens = 2;
    for(unsigned long i = 0; i < pathlen; i++) {
        buffer[i] = path[i];
        if(buffer[i] == ':' && colon_offset == -1) {
            colon_offset = i;
            buffer[i] = '\0';
        }
        if(buffer[i] == '/') {
            buffer[i] = '\0';
            total_num_opens++;
        }
    }

    unsigned long dir_perm_flags = 0;
    unsigned long dir_mode_flags = 0;

#define PERM_FLAGS (cur_open == total_num_opens ? perm_flags : dir_perm_flags)
#define MODE_FLAGS (cur_open == total_num_opens ? mode_flags : dir_mode_flags)

    fd_t cur_parent = NULL_FD;
    char *cur_name;

    int cur_open = 1;

    if(colon_offset != -1) {
        char *mount_name = buffer;
        cur_parent = sys_open(
                NULL_FD,
                mount_name,
                PERM_FLAGS,
                MODE_FLAGS);
        cur_open++;
        if(cur_parent == NULL_FD)
        {
            return NULL_FD;
        }
        cur_name = buffer + (colon_offset+1);
    } else {
        cur_parent = sys_open(
                NULL_FD,
                "",
                PERM_FLAGS,
                MODE_FLAGS);
        cur_open++;
        cur_name = buffer;
    }

    while(cur_name < buffer_end) {
        size_t namelen = strlen(cur_name);
        fd_t cur;
        cur = sys_open(
                cur_parent,
                cur_name,
                PERM_FLAGS,
                MODE_FLAGS);
        cur_open++;
        if(cur == NULL_FD) {
            if(cur_parent != NULL_FD) {
                sys_close(cur_parent);
            }
            return NULL_FD;
        }
        if(cur_parent != NULL_FD) {
            sys_close(cur_parent);
        }

        cur_name += namelen + 1;
        cur_parent = cur;
    }

    return cur_parent;
}

