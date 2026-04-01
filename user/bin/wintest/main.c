
#include <windd/windd.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, const char **argv)
{
    int res;

    res = windd_client_init();
    if(res) {
        fprintf(stderr, "Failed to initialize windd library!\n");
        return -1;
    }

    struct window *window = NULL;
    window = windd_client_open();

    if(window != NULL) {
        printf("Opened client window!\n");
    } else {
        printf("Failed to create client window!\n");
    }

    windd_client_close(window);
    return 0;
}

