#ifndef __KANAWHA__RAMFILE_H__
#define __KANAWHA__RAMFILE_H__

#include <kanawha/stdint.h>

int
create_ramfile(
        const char *ramfile_name,
        paddr_t paddr,
        size_t size); 

int
destroy_ramfile(const char *ramfile_name);

struct fs_mount *
ramfile_mount(void);

struct fs_node *
ramfile_get(const char *name);

int
ramfile_put(
        struct fs_node *node);

#endif
