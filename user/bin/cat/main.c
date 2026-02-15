
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#define BUFSIZE 512

int main(int argc, const char **argv)
{
    if(argc < 2) {
        return 0;
    }

    const char *path = argv[1];

    FILE *file = fopen(path, "r");
    if(file == NULL) {
        puts("Failed to open file!\n");
        return -1;
    }

    uint8_t *buffer = malloc(BUFSIZE);
    if(buffer == NULL) {
        puts("Failed to allocate buffer!\n");
        return -1;
    }

    size_t read;
    size_t written;

    while(1)
    {
        read = fread(buffer, 1, BUFSIZE, file);
        if(read == 0) {
            // EOF
            break;
        }

        size_t cur_written = 0;
        while(cur_written < read) {
            written = fwrite(buffer + cur_written, 1, read - cur_written, stdout);
            if(written == 0) {
                // EOF/Failure
                break;
            }
            cur_written += written;
        }
    }

    free(buffer);

    return 0;
}

