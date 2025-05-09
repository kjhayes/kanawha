#ifndef __KANAWHA__ACPI_NAMESPACE_H__
#define __KANAWHA__ACPI_NAMESPACE_H__

#include <kanawha/types.h>
#include <kanawha/list.h>
#include <kanawha/spinlock.h>

struct acpi_ns_node
{
    // May be NULL
    struct acpi_obj *object;

    spinlock_t hierarchy_lock;
    struct acpi_ns_node *parent;
    ilist_t children;
    ilist_node_t child_node;
};

#endif
