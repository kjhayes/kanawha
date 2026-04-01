
#include <windd/windd.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/mmap.h>

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

    void *buffer;
    res = kanawha_sys_mmap(
            window->conn,
            0,
            &buffer,
            0x1000,
            MMAP_SHARED|MMAP_PROT_READ|MMAP_PROT_WRITE);
    if(res) {
        fprintf(stderr, "Failed to map first page of connection buffer!\n");
        return -1;
    }

    while(*(char*)buffer == '\0') {
        printf("waiting...\n");
    }

    sleep(1);

    puts((char*)buffer);

    windd_client_close(window);
    return 0;
}

