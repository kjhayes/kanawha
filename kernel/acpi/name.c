
#include <acpi/name.h>
#include <acpi/namespace.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <kanawha/errno.h>

struct acpi_path *
acpi_path_create(
        size_t length,
        int parent_prefix_count)
{
    struct acpi_path *path =
	kmalloc(sizeof(struct acpi_path) + (length * sizeof(struct acpi_name)),
		KM_KERNEL);
    if(path == NULL) {
        return NULL;
    }

    path->prefixes = parent_prefix_count;
    path->pathlen = length;
    memset(path->names, 0, sizeof(struct acpi_name) * length);

    return path;
}

void
acpi_path_destroy(
        struct acpi_path *path)
{
    kfree(path);
}

struct acpi_path *
acpi_path_clone(
	struct acpi_path *path)
{
    struct acpi_path *clone = acpi_path_create(
	    path->pathlen,
	    path->prefixes);
    if(clone == NULL) {
	return NULL;
    }
    memcpy(clone->names, path->names, sizeof(struct acpi_name) * clone->pathlen);
    return clone;
}

struct acpi_path *
acpi_path_create_absolute(
	struct acpi_node *scope,
	struct acpi_path *relpath)
{
    if(relpath->prefixes == ACPI_PATH_PREFIX_ROOT) {
	return acpi_path_clone(relpath);
    }

    acpi_node_get(scope);
    for(size_t i = 0; i < relpath->prefixes; i++) {
	struct acpi_node *old = scope;
	scope = acpi_node_get_parent(scope);
	acpi_node_put(old);
	if(scope == NULL) {
	    wprintk("acpi_path_create_absolute: Failed to create path from relative path with invalid number of prefixes!\n");
	    return NULL;
	}
    }

    size_t num_ancestors = 0;
    struct acpi_node *ancestor = scope;
    acpi_node_get(ancestor);
    while(1) {
	struct acpi_node *old = ancestor;
	ancestor = acpi_node_get_parent(ancestor);
	acpi_node_put(old);

	if(ancestor == NULL) {
	    break;
	}

	num_ancestors++;
    }

    size_t pathlen = relpath->pathlen + num_ancestors;
    struct acpi_path *abs_path = acpi_path_create(pathlen, ACPI_PATH_PREFIX_ROOT);
    if(abs_path == NULL) {
	acpi_node_put(scope);
	wprintk("acpi_path_create_absolute: Failed to allocate path!\n");
	return NULL;
    }

    ancestor = scope;
    acpi_node_get(ancestor);
    for(size_t i = 0; i < num_ancestors; i++)
    {
	if(ancestor == NULL) {
	    // Unexpected
	    acpi_node_put(scope);
	    acpi_path_destroy(abs_path);
	    wprintk("acpi_path_create_absolute: Failed to get path ancestor (Unexpected)!\n");
	    return NULL;
	}

	abs_path->names[(num_ancestors-1)-i] = acpi_node_get_name(ancestor);

	struct acpi_node *old = ancestor;
	ancestor = acpi_node_get_parent(ancestor);
	acpi_node_put(old);
    }

    memcpy(&abs_path->names[num_ancestors], relpath->names, relpath->pathlen * sizeof(struct acpi_name));

    return abs_path;
}

// Returns 0 on success
int
acpi_verify_name(
        struct acpi_name *name)
{
    char c = name->raw[0];
    if(!
      (c == '_' ||
      (c >= 'A' && c <= 'Z')
      ))
    {
        return -EINVAL;
    }

    for(int i = 1; i < 4; i++) {
        c = name->raw[i];
        if(!
          (c == '_' ||
          (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9')
          ))
        {
            return -EINVAL;
        }
    }

    return 0;
}

// Returns 0 on success
int
acpi_verify_path(
        struct acpi_path *path)
{
    if(path->prefixes < -1) {
        return -EINVAL;
    }
    for(size_t i = 0; i < path->pathlen; i++) {
        struct acpi_name *name = &path->names[i];
        int res = acpi_verify_name(name);
        if(res) {
            return res;
        }
    }

    return 0;
}

int
acpi_dump_name(
        printk_f *printer,
        struct acpi_name *name)
{
    {
	char c = name->raw[0];
	if(c == '_' || (c >= 'A' && c <= 'Z')) {
	    (*printer)("%c", c);
	} else {
	    (*printer)("{Invalid-Char-0x%x}", (unsigned int)c);
	}
    }
    for(size_t i = 1; i < 4; i++) {
	char c = name->raw[i];
	if(c == '_' || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
	    (*printer)("%c", c);
	} else {
	    (*printer)("{Invalid-Char-0x%x}", (unsigned int)c);
	}
    }
    return 0;
}

int
acpi_dump_path(
        printk_f *printer,
        struct acpi_path *path)
{
    int res;

    if(path->prefixes == -1) {
        (*printer)("\\");
    }

    for(int i = 0; i < path->prefixes; i++) {
        (*printer)("^");
    }

    for(size_t i = 0; i < path->pathlen; i++) {
        if(i > 0) {
            (*printer)(".");
        }
        struct acpi_name *name = &path->names[i];
        res = acpi_dump_name(printer, name);
        if(res) {
            return res;
        }
    }

    return 0;
}

