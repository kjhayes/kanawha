
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

__attribute__((weak))
void *calloc(size_t nmemb, size_t size)
{
    size_t total_size = nmemb * size;

    // mmap will zero the region for us
    void *addr = malloc(total_size);
    if(addr == NULL) {
        return addr;
    }

    memset(addr, 0, total_size);
    return addr;
}

