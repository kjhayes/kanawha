
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <kanawha/syscall.h>

// #define BYTE_BY_BYTE
#define BUFSIZE 0x10000

int
main(int argc, const char **argv)
{
    if(argc < 2)
    {
        return 0;
    }

    const char *path = argv[1];

    FILE *file = fopen(path, "r");
    if(file == NULL)
    {
        puts("Failed to open file!\n");
        return -1;
    }

#ifdef BYTE_BY_BYTE
    ssize_t amt;
    int fd = fileno(file);
    char c;
    while(1) {
        amt = kanawha_sys_read(fd, &c, 1);
        if(amt < 0) {
            return amt;
        }
        if(amt == 0) {
            break;
        }
        amt = kanawha_sys_write(1, &c, 1);
        if(amt < 0) {
            return amt;
        }
    }
    return 0;
#else
    uint8_t *buffer = malloc(BUFSIZE);
    if(buffer == NULL)
    {
        puts("Failed to allocate buffer!\n");
        return -1;
    }

    size_t read;
    size_t written;

    while(1)
    {
        read = fread(buffer, 1, BUFSIZE, file);
        if(read == 0)
        {
            // EOF
            break;
        }

        size_t cur_written = 0;
        while(cur_written < read)
        {
            written =
                fwrite(buffer + cur_written, 1, read - cur_written, stdout);
            if(written == 0)
            {
                // EOF/Failure
                break;
            }
            cur_written += written;
        }
    }

    free(buffer);
#endif

    return 0;
}
