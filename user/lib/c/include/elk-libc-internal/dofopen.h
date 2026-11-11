#ifndef __ELK_LIBC_INTERNAL__DOFOPEN_H__
#define __ELK_LIBC_INTERNAL__DOFOPEN_H__

#include <elk-libc-internal/FILE.h>

int
__elk_libc_internal__dofopen(const char *restrict path,
                             const char *restrict mode,
                             FILE *file);

#endif
