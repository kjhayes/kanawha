#define __ELK_DL__INTERNAL__
#include <dlfcn.h>
#include <errno.h>

int
dlclose(void *handle)
{
    return -EUNIMPL;
}
