
#include <kanawha/file.h>
#include <kanawha/syscall.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int
main(int argc, const char **argv)
{
    int res;

    if(argc != 2)
    {
        fprintf(stderr, "Usage: %s [path]\n", argv[0]);
        return -1;
    }

    const char *path = argv[1];

    mkdir(path, 0);

    return 0;
}
