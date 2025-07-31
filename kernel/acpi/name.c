
#include <acpi/name.h>
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
    (*printer)("%c%c%c%c",
            name->raw[0],
            name->raw[1],
            name->raw[2],
            name->raw[3]
            );
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

