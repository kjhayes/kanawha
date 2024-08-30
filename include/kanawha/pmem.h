#ifndef __KANAWHA__PMEM_H__
#define __KANAWHA__PMEM_H__

#include <kanawha/vmem.h>
#include <kanawha/util/ptree.h>

struct pmem_region {
    struct ptree_node ptree_node;
    size_t size;
    unsigned long flags;
};

#endif
