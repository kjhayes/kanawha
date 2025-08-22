#ifndef __KANAWHA__RAMFILE_H__
#define __KANAWHA__RAMFILE_H__

#include <kanawha/types.h>
#include <kanawha/pointer.h>

int
create_ramfile(
        const char *ramfile_name,
        void __phys * paddr,
        size_t size); 

int
destroy_ramfile(const char *ramfile_name);

struct fs_mount *
ramfile_mount(void);

#endif
