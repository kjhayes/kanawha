
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <kanawha/sleep.h>
#include <kanawha/sys-wrappers.h>

const char *progname = "sleep";

__attribute__((noreturn))
static void
panic_usage(void) {
    fprintf(stderr, "Usage: %s [MS]\n",
            progname);
    exit(EXIT_FAILURE);
}

int
main(int argc, const char **argv)
{
    if(argc > 0) {
        progname = argv[0];
    }

    if(argc != 2) {
        panic_usage();
    }

    int ms = atoi(argv[1]);
    kanawha_sys_sleep(ms, SLEEP_DURATION_MSEC);

    return 0;
}

