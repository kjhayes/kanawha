#ifndef __KANAWHA__ACPI_NAMESPACE_H__
#define __KANAWHA__ACPI_NAMESPACE_H__

#include <acpi/name.h>
#include <acpi/object.h>

struct acpi_namespace;
struct acpi_node;

struct acpi_namespace *
acpi_default_namespace(void);

// Increment the refcount
void
acpi_node_get(
	struct acpi_node *node);

// Decrement the refcount (free if zero)
void
acpi_node_put(
	struct acpi_node *node);

struct acpi_node *
acpi_node_get_parent(
	struct acpi_node *node);

// Returns NULL or node with incremented refcount
struct acpi_node *
acpi_namespace_get_root(
	struct acpi_namespace *ns);

// Returns NULL or node with incremented refcount
struct acpi_node *
acpi_node_lookup_name(
	struct acpi_node *node,
	struct acpi_name *name);

// Returns NULL or node with incremented refcount
struct acpi_node *
acpi_node_lookup(
	struct acpi_node *scope,
	struct acpi_path *path);

// Returns NULL or node with incremented refcount
int
acpi_node_create_named_object(
	struct acpi_node *scope,
	struct acpi_path *path,
	struct acpi_obj *object);

struct acpi_obj *
acpi_node_get_named_object(
	struct acpi_node *scope,
	struct acpi_path *path);

void
acpi_namespace_dump(
	printk_f *printer,
	struct acpi_namespace *ns);

void
acpi_node_dump_path(
	printk_f *printer,
	struct acpi_node *node);

struct acpi_name
acpi_node_get_name(
	struct acpi_node *node);

#endif
