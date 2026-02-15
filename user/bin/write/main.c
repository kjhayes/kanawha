
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

const char *progname = "write";

__attribute__((noreturn))
static void
panic_usage(void) {
    fprintf(stderr, "Usage: %s [-o] [-a] [-n NUM > 0] [-f filename] ARGS\n",
            progname);
    exit(EXIT_FAILURE);
}

int
main(int argc, const char **argv)
{
    if(argc > 0) {
        progname = argv[0];
    }

    int overwrite = 0;
    int append = 0;
    int repeat = 0;
    int number_per_arg = 1;
    const char *path = NULL;

    int opt;
    while((opt = getopt(argc, (char **)argv, "oarf:n:")) != -1) {
        switch(opt) {
            case 'o':
                append = 1;
                overwrite = 1;
                break;
            case 'a':
                append = 1;
                break;
            case 'f':
                path = optarg;
                break;
            case 'r':
                repeat = 1;
                break;
            case 'n':
                number_per_arg = atoi(optarg);
                break;
            default:
                panic_usage();
        }
    }

    if(path == NULL) {
        panic_usage();
    }

    if(number_per_arg == 0) {
        panic_usage();
    }

    int pos_argc = argc - optind;
    if(pos_argc < 0) {pos_argc = 0;}
    const char **pos_argv = argv + optind;

    const char *open_flags;
    if(append) {
        open_flags = "a";
    } else {
        open_flags = "w";
    }

    FILE *target = fopen(path, open_flags);
    if(target == NULL) {
        fprintf(stderr, "Could not open or create file \"%s\"!\n", path);
        exit(EXIT_FAILURE);
    }

    size_t size = 0;
    fseek(target, 0, SEEK_END);
    size = ftell(target);

    if(overwrite) {
        fseek(target, 0, SEEK_SET);
    }

    size_t written = 0;
    do {
        for(int i = 0; i < pos_argc; i++) {
            const char *str = pos_argv[i];
            for(int n = 0; n < number_per_arg; n++) {
                fputs(str, target);
                written += strlen(str);
                if(written >= size) {
                    break;
                }
            }
        }
    } while(repeat && written < size);

    fflush(target);

    return 0;
}

