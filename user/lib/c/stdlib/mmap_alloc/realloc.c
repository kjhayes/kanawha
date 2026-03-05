
#include <kanawha/sys-wrappers.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void *
realloc(void *ptr, size_t size)
{
    if(ptr != NULL)
    {
        void *original_alloc = (void *)((uintptr_t)ptr & ~0xFFF);
        uint64_t *original_sizes = (uint64_t *)original_alloc;

        size_t original_size = original_sizes[0];

        void *new_alloc = malloc(size);
        if(new_alloc == NULL)
        {
            return NULL;
        }

        size_t to_copy = size < original_size ? size : original_size;

        memcpy(new_alloc, ptr, to_copy);

        free(ptr);

        return new_alloc;
    }
    else
    {
        return malloc(size);
    }
}
