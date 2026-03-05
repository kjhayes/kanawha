
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *progname = "rm";

__attribute__((noreturn)) static void
panic_usage(void)
{
    fprintf(stderr, "Usage: %s [PATH]\n", progname);
    exit(EXIT_FAILURE);
}

int
main(int argc, const char **argv)
{
    int res;

    if(argc > 0)
    {
        progname = argv[argc];
    }

    const char *path = NULL;

    int opt;

    while((opt = getopt(argc, (char **)argv, "")) != -1)
    {
        switch(opt)
        {
        default:
            panic_usage();
        }
    }

    int pos_argc = argc - optind;
    const char **pos_argv = argv + optind;
    if(pos_argc == 1)
    {
        path = pos_argv[0];
    }
    else
    {
        panic_usage();
    }

    res = unlink(path);
    if(res)
    {
        fprintf(stderr, "Failed to unlink \"%s\"!\n", path);
        return res;
    }

    return 0;
}
