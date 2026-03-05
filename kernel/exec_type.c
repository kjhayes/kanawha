
#include <kanawha/exec_type.h>

DEFINE_REGISTRY(exec_type,
                registry_node,
                REGISTRY_NO_INIT_FUNCTION,
                REGISTRY_NO_DEINIT_FUNCTION);

int
exec_type_probe_always_maybe(struct exec_type *exec_type,
                             void *hdr,
                             size_t hdrlen)
{
    return EXEC_TYPE_PROBE_MAYBE;
}
