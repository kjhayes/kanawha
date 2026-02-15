
#include <stdio.h>
#include <stdlib.h>

#define BUFSIZE 0x1000

const char *progname = "cp";

int main(int argc, const char **argv)
{
    if(argc > 0) {
        progname = argv[0];
    }
    if(argc != 3) {
        fprintf(stderr, "USAGE: %s [SRC_PATH] [DST_PATH]\n",
                progname);
        exit(-1);
    }

    char *buf = malloc(BUFSIZE);
    if(buf == NULL) {
        return -1;
    }

    const char *src_path = argv[1];
    const char *dst_path = argv[2];

    FILE *src_file =
        fopen(src_path, "r");
    if(src_file == NULL) {
        fprintf(stderr,
                "Failed to open file \"%s\"\n",
                src_path);
        exit(-1);
    }
    FILE *dst_file =
        fopen(dst_path, "w");
    if(dst_file == NULL) {
        fprintf(stderr,
                "Failed to open or create file \"%s\"\n",
                dst_path);
        exit(-1);
    }

    while(1) {
        size_t read = fread(buf, 1, BUFSIZE, src_file);
        if(read == 0) {
            break;
        }

        size_t written = 0;
        while(written < read) {
            written += fwrite(buf + written, 1, read - written, dst_file);
            if(written == 0) {
                fprintf(stderr,
                        "Error occurred while writing to file \"%s\"\n",
                        dst_path);
                exit(-1);
            }
        }
    }

    fclose(src_file);
    fclose(dst_file);
    free(buf);

    return 0;
}

