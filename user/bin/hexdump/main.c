
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

const char *progname = "hexdump";

static void 
dump_usage(FILE *file)
{
    fprintf(file,
            "USAGE: %s [FILE]\n",
            progname);
}

static void 
panic_usage(
        const char *fmt,
        ...)
{
    fprintf(stderr, "Invalid Arguments: ");

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    
    fprintf(stderr, "\n");

    dump_usage(stderr);
    exit(-1);
}

int main(int argc, const char **argv) 
{
    if(argc > 0) {
        progname = argv[0];
    }
    if(argc < 2) {
        panic_usage("Too Few Arguments");
    }

    const char *filepath = argv[1];

    FILE *file = fopen(
            filepath,
            "r");
    if(file == NULL) {
        fprintf(stderr, "Failed to open file: %s\n", filepath);
        exit(-1);
    }

    // Don't be smart here, just read byte by byte.
    // (Also helps stress test the kernel a bit)

    uint8_t buf;
    int bytes_cur_line = 0;
    int bytes_per_line = 16;

    while(1)
    {
        size_t read = fread(
            &buf,
            1,
            1,
            file);
        if(read == 0) {
            // EOF
            break;
        }

        uint8_t lownib = buf & 0xF;
        uint8_t highnib = (buf & 0xF0) >> 4;

        char highc = highnib < 10 ? '0' + highnib : 'A' + (highnib-10);
        char lowc  = lownib  < 10 ? '0' + lownib  : 'A' + (lownib -10);

        putchar(' ');
        putchar(highc);
        putchar(lowc);

        bytes_cur_line++;
        if(bytes_cur_line >= bytes_per_line) {
            putchar('\n');
            bytes_cur_line = 0;
        }
    }
    if(bytes_cur_line > 0) {
        putchar('\n');
    }

    return 0;
}

