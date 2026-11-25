
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "log.h"

static const char *progname = "bench";

#define CMD_XLIST(X, ...)\
X(fork, "fork", ##__VA_ARGS__)\
X(lens, "lens", ##__VA_ARGS__)\

#define XCASE(__NAME, __STR, ...)\
    int __NAME ## _main(int argc, const char **argv);
    CMD_XLIST(XCASE)
#undef XCASE

static inline void
print_usage(FILE *file)
{
    fprintf(stderr, "USAGE: %s [help",
            progname);
#define XCASE(__NAME, __STR, ...)\
    fprintf(stderr, ", " __STR);
    CMD_XLIST(XCASE)
#undef XCASE
    fprintf(stderr, "]\n");
}

static inline int
panic_usage(void) {
    print_usage(stderr);
    exit(-1);
}

int main(int argc, const char **argv)
{
    if(argc < 2) {
        panic_usage();
    }

    const char *name = argv[1];
    if(strcmp("help", name) == 0) {
        print_usage(stdout);
        return 0;
    }
#define XCASE(__NAME, __STR, ...)\
    else if(strcmp(__STR, name) == 0) {\
        return __NAME ## _main(argc - 1, argv + 1);\
    }
    CMD_XLIST(XCASE)
    else {
        ERROR("Unrecognized subcommand %s\n", name);
        panic_usage();
    }
#undef XCASE
    return -EINVAL;
}

