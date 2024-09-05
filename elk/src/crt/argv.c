
#include <elk/syscall.h>
#include <kanawha/uapi/mmap.h>
#include <kanawha/uapi/environ.h>
#include <kanawha/uapi/errno.h>

static size_t
strlen(char *str)
{
    size_t len = 0;
    while(*str) {
        str++;
        len++;
    }
    return len;
}

#define ARGV_ENV_KEY "ARGV"

#define ARGV_REGION_SIZE 0x1000
#define ARGV_REGION_BASE 0x2000000

void
__elk_crt__get_argv(
        int *argc_out,
        const char ***argv_out)
{
    int res;
    res = sys_mmap(
            NULL_FD,
            0,
            (void*)ARGV_REGION_BASE,
            ARGV_REGION_SIZE,
            MMAP_PROT_READ|MMAP_PROT_WRITE,
            MMAP_ANON);
    if(res) {
        sys_exit(1);
    }

    void *region_base = (void*)ARGV_REGION_BASE;

    res = sys_environ(
            ARGV_ENV_KEY,
            region_base,
            ARGV_REGION_SIZE,
            ENV_GET);
    if(res == -ENXIO) {
        sys_munmap((void*)ARGV_REGION_BASE);
        *argc_out = 0;
        *argv_out = NULL;
        return;
    }
    else if(res) {
        sys_exit(res);
    }

    char *end = region_base + ARGV_REGION_SIZE;
    *(end-1) = '\0';

    size_t argv_len = strlen(region_base) + 1;

    size_t room_left = ARGV_REGION_SIZE - argv_len;
    if(room_left >= ARGV_REGION_SIZE) {
        // Underflow
        sys_exit(1);
    }

    const char **argv_ptr = (const char **)(end - room_left);
    size_t argc_max = room_left / sizeof(const char*);

    int argc = 0;

    for(size_t i = 0; i < argv_len; i++) {
        char c = ((char*)region_base)[i];
        if(c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            ((char*)region_base)[i] = '\0';
        }
    }

    char *iter = region_base;
    size_t len_left = argv_len;
    while((uintptr_t)iter < (uintptr_t)argv_ptr && len_left > 0) {
        char *cur = iter;
        size_t cur_len = strlen(cur);
        if(cur_len > 0) {
            if(argc < argc_max) {
                argv_ptr[argc] = cur;
                argc++;
            } else {
                // Too many or too long argument(s)
                sys_exit(1);
            }
        }
        iter += cur_len + 1;
    }

    *argc_out = argc;
    *argv_out = argv_ptr;

    return;
}

