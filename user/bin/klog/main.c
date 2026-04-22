
#include <stdio.h>
#include <unistd.h>

#define KLOG_PATH "/sys/info/klog"

int
main(int argc, const char **argv)
{
    FILE *klog = fopen(KLOG_PATH, "r");
    if(klog == NULL)
    {
        fprintf(stderr, "Failed to open \"%s\"!\n", KLOG_PATH);
    }
    while(1)
    {
        char c = fgetc(klog);
        if(c == EOF)
        {
            usleep(100);
            continue;
        }
        else
        {
            fputc(c, stdout);
        }
    }

    fclose(klog);
    return 0;
}
