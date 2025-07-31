
#include <acpi/target.h>
#include <acpi/name.h>
#include <acpi/term.h>
#include <kanawha/kmalloc.h>
#include <kanawha/printk.h>
#include <kanawha/errno.h>

static inline struct acpi_target *
__alloc_target(void)
{
    struct acpi_target *target =
        kmalloc(sizeof(*target), KM_KERNEL);
    return target;
}

struct acpi_target *
acpi_create_null_target(void)
{
    struct acpi_target *target = __alloc_target();
    if(target == NULL) {
        return NULL;
    }
    
    target->type = ACPI_TARGET_NULL;

    return 0;
}

struct acpi_target *
acpi_create_debug_target(void)
{
    struct acpi_target *target = __alloc_target();
    if(target == NULL) {
        return NULL;
    }
    
    target->type = ACPI_TARGET_DEBUG;

    return 0;
}

struct acpi_target *
acpi_create_named_target(
        struct acpi_path *path)
{
    struct acpi_target *target = __alloc_target();
    if(target == NULL) {
        return NULL;
    }
    
    target->type = ACPI_TARGET_NAME;
    target->typed_data.name.path = path;

    return 0;
}

struct acpi_target *
acpi_create_term_target(
        struct acpi_term *term)
{
    struct acpi_target *target = __alloc_target();
    if(target == NULL) {
        return NULL;
    }
    
    target->type = ACPI_TARGET_TERM;
    target->typed_data.term.term = term;

    return 0;
}

int
acpi_destroy_target(
        struct acpi_target *target)
{
    switch(target->type) {
        case ACPI_TARGET_NULL:
        case ACPI_TARGET_DEBUG:
            break;
        case ACPI_TARGET_NAME:
            acpi_path_destroy(target->typed_data.name.path);
            break;
        case ACPI_TARGET_TERM:
            acpi_destroy_term(target->typed_data.term.term);
            break;
        default:
            eprintk("acpi_destroy_target: Recevied target with invalid type!\n");
            return -EINVAL;
    }

    kfree(target);

    return 0;
}

int
acpi_dump_target(
        struct acpi_target *target,
        printk_f *printer,
        int depth)
{
    switch(target->type) {
        case ACPI_TARGET_NULL:
            acpi_dump_term_indent(printer, depth);
            (*printer)("NULL-TARGET\n");
            break;
        case ACPI_TARGET_DEBUG:
            acpi_dump_term_indent(printer, depth);
            (*printer)("DEBUG-TARGET\n");
            break;
        case ACPI_TARGET_NAME:
            acpi_dump_term_indent(printer, depth);
            acpi_dump_path(printer, target->typed_data.name.path);
            (*printer)("\n");
            break;
        case ACPI_TARGET_TERM:
            acpi_dump_term(target->typed_data.term.term, printer, depth);
            break;
        default:
            acpi_dump_term_indent(printer, depth);
            (*printer)("INVALID-TARGET");
            (*printer)("\n");
            return -EINVAL;
    }
    return 0;
}

