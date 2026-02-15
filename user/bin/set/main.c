
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

const char *progname = "set";

__attribute__((noreturn))
static void
panic_usage(void) {
    fprintf(stderr, "Usage: %s [-f OUTPUT-PATH] [-n VALUE] [-i INPUT-PATH]\n",
            progname);
    exit(EXIT_FAILURE);
}

int
main(int argc, const char **argv)
{
    if(argc > 0) {
        progname = argv[0];
    }

    const char *path = NULL;
    int value = 0;
    const char *input_path = NULL;

    int opt;
    while((opt = getopt(argc, (char **)argv, "f:n:i:")) != -1) {
        switch(opt) {
           case 'f':
                path = optarg;
                break;
           case 'n':
                value = atoi(optarg);
                break;
           case 'i':
                input_path = optarg;
                break;
           default:
                panic_usage();
        }
    }

    if(path == NULL) {
        panic_usage();
    }

    int pos_argc = argc - optind;
    if(pos_argc < 0) {pos_argc = 0;}
    const char **pos_argv = argv + optind;

    const char *open_flags;
    open_flags = "a";

    FILE *target = fopen(path, open_flags);
    if(target == NULL) {
        fprintf(stderr, "Could not open or create file \"%s\"!\n", path);
        exit(EXIT_FAILURE);
    }
    printf("Opened \"%s\"\n", path);

    size_t size = 0;
    fseek(target, 0, SEEK_END);
    size = ftell(target);
    fseek(target, 0, SEEK_SET);

    void *buffer = malloc(size);
    if(buffer == NULL) {
        printf("Failed to allocate buffer!\n");
        exit(-1);
    }
    memset(buffer, value, size);

    printf("Saved buffer in memory of size=0x%lx\n", (unsigned long)size);

    if(input_path != NULL) {
        FILE *input_file = fopen(input_path, "r");
        if(input_file == NULL) {
            fprintf(stderr, "Could not open file \"%s\"!\n", input_path);
            exit(EXIT_FAILURE);
        }
        fread(buffer, size, 1, input_file);
    }

    fwrite(buffer, size, 1, target);

    fflush(target);

    return 0;
}

