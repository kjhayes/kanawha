
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int
ansiterm_get_cursor(
        unsigned long *x,
        unsigned long *y)
{
    printf("\033[6n");
    fflush(stdout);

#define BUFLEN (64)

    char buffer[BUFLEN+1];
    size_t len = 0;
    while(len < BUFLEN) {
        buffer[len] = fgetc(stdin);
        len++;
        if(buffer[len-1] == 'R') {
            break;
        }
        if(len >= BUFLEN) {
            fprintf(stderr, "terminal response too long!\n");
            exit(EXIT_FAILURE);
        }
    }

    buffer[BUFLEN] = '\0';

    size_t csi = 0;
    while(csi < BUFLEN && buffer[csi] != '\033') {
        csi++;
    }
    if(buffer[csi] != '\033') {
        fprintf(stderr, "terminal did not respond with an ANSI escape code!\n");
        exit(EXIT_FAILURE);
    }

    size_t max_len = len - csi;
    if(max_len < 5) {
        fprintf(stderr, "terminal response too short!\n");
        exit(EXIT_FAILURE);
    }

    if(buffer[csi+1] != '[') {
        fprintf(stderr, "terminal did not respond with a CSI escape code!\n");
        exit(EXIT_FAILURE);
    }

    size_t y_start = csi+2;
    size_t y_chars = 0;
    while(y_start + y_chars < BUFLEN && isdigit(buffer[y_start + y_chars])) {
        y_chars++;
    }

    if(buffer[y_start + y_chars] != ';') {
        fprintf(stderr, "terminal response did not delimit y and y properly!\n");
        exit(EXIT_FAILURE);
    }

    size_t x_start = y_start + y_chars + 1;
    size_t x_chars = 0;
    while(x_start + x_chars < BUFLEN && isdigit(buffer[x_start + x_chars])) {
        x_chars++;
    }
    
    if(buffer[x_start + x_chars] != 'R') {
        fprintf(stderr, "terminal response did not terminate correctlx!\n");
        exit(EXIT_FAILURE);
    }

    char x_buffer[BUFLEN] = {0};
    memcpy(x_buffer, buffer + x_start, x_chars);
    char y_buffer[BUFLEN] = {0};
    memcpy(y_buffer, buffer + y_start, y_chars);

    *x = strtoul(x_buffer, NULL, 10);
    *y = strtoul(y_buffer, NULL, 10);
    return 0;
}

int
ansiterm_set_cursor(
        unsigned long x,
        unsigned long y)
{
    printf("\033[%lu;%luH",
            x, y);
    fflush(stdout);
    return 0;
}

int
ansiterm_get_dimensions(
        unsigned long *width,
        unsigned long *height)
{
    unsigned long x,y;
    ansiterm_get_cursor(&x, &y);
    ansiterm_set_cursor(999, 999);
    ansiterm_get_cursor(width, height);
    ansiterm_set_cursor(x, y);
    return 0;
}

