#ifndef __KANAWHA__RAMFILE_H__
#define __KANAWHA__RAMFILE_H__

#include <kanawha/stdint.h>
#include <kanawha/aspace.h>

int
create_ramfile(
        const char *ramfile_name,
        void __phys * paddr,
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
