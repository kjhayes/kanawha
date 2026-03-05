
#include <stdio.h>
#include <unistd.h>

int
main(int argc, const char **argv)
{
    size_t index = 0;
    while(1)
    {
        if(environ[index] == NULL)
        {
            break;
        }
        printf("%s\n", environ[index]);
        index++;
    }
    return 0;
}
