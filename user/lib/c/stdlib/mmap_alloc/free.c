
#include <kanawha/sys-wrappers.h>

#include <assert.h>
#include <stddef.h>

void
free(void *ptr)
{
    int res;

    if(ptr == NULL)
    {
        return;
    }

    void *base_ptr = (void *)((uintptr_t)ptr & ~0xFFF);

    res = kanawha_sys_munmap(ptr);
    while(res != 0)
    {
    }
    // assert(res == 0);
}
