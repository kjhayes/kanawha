
#include <stddef.h>
#include <stdlib.h>

void *aligned_alloc(size_t alignment, size_t size)
{
    if(alignment <= 16) {
        return malloc(size);
    }

    if(alignment > 512) {
        return NULL;
    }

    size_t padding_amount = alignment - 16;
    
    void *data = malloc(size + padding_amount);
    data += padding_amount;
    return data;
}

