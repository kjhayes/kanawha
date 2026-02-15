
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

    size_t line_size = 80;
    size_t tab_size = 4;

    size_t starting_lines = 25;

    int hit_eof = 0;
    while(!hit_eof) {
        for(size_t i = 0; i < line_size;) {
            char c = getc(file);
            if(c == EOF) {
                hit_eof = 1;
                break;
            }
            switch(c) {
                case '\n':
                    i += line_size;
                    break;
                case '\r':
                    continue;
                case '\t':
                    i += tab_size;
                    break;
                default:
                    i += 1;
                    break;
            }
            putchar(c);
        }

        if(hit_eof) {
            break;
        }

        if(starting_lines > 0) {
            starting_lines--;
        } else {
            char input = getchar(); // Wait for input
            if(input == EOF) {
                break;
            }
            if(input == 'q' || input == 'Q') {
                break;
            }
        }
    }

    return 0;
}

