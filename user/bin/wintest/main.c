
#include <windd/windd.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, const char **argv)
{
    struct window *window = NULL;
    window = windd_client_open();

    printf("Opened client window!\n");

    windd_client_close(window);
    return 0;
}

