
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define ELK_LIBC_GETLINE_BASE_SIZE (0x100)

ssize_t
getline(
        char **restrict lineptr,
        size_t *restrict nptr,
        FILE *restrict stream)
{
    char *line = *lineptr;
    size_t n = *nptr;
    if(line == NULL) {
        line = malloc(ELK_LIBC_GETLINE_BASE_SIZE);
        n = ELK_LIBC_GETLINE_BASE_SIZE;
    }

    if(line == NULL) {
        *lineptr = NULL;
        *nptr = 0;
        return -ENOMEM;
    }

    ssize_t amt_read = 0;
    while(1) {
        char c = fgetc(stream);

        if(amt_read >= n) {
            n *= 2;
            char *new = realloc(line, n);
            if(new == NULL) {
                free(line);
                *lineptr = NULL;
                *nptr = 0;
                return -ENOMEM;
            }
        }

        line[amt_read] = c;
        amt_read++;

        if(c == '\n') {
            break;
        }
    }

    if(amt_read >= n) {
        n *= 2;
        char *new = realloc(line, n);
        if(new == NULL) {
            free(line);
            *lineptr = NULL;
            *nptr = 0;
            return -ENOMEM;
        }
    }
    line[amt_read] = '\0';

    *lineptr = line;
    *nptr = n;

    return amt_read;
}

