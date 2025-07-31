
#include <acpi/term.h>
#include <acpi/name.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>

struct acpi_scope_term {
    struct acpi_term term;
    struct acpi_path *path;
    struct acpi_termlist *terms;
};

static int
__acpi_destroy_scope_term(
        struct acpi_term *term)
{
    struct acpi_scope_term *sterm =
        container_of(term, struct acpi_scope_term, term);

    acpi_path_destroy(sterm->path);
    acpi_destroy_termlist(sterm->terms);
    kfree(term);

    return 0;
}

static int
__acpi_eval_scope_term(
        struct acpi_term *term,
        struct acpi_eval_ctx *ctx,
        struct acpi_obj **obj_out)
{
    wprintk("ACPI tried to evaluate scope term!\n");
    return -EUNIMPL;
}

static int
__acpi_dump_scope_term(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    struct acpi_scope_term *sterm =
        container_of(term, struct acpi_scope_term, term);
    acpi_dump_term_indent(printer, depth);
    (*printer)("SCOPE(");
    acpi_dump_path(printer, sterm->path);
    (*printer)(")\n");
    acpi_dump_termlist(
            sterm->terms,
            printer,
            depth);
    return 0;
}

struct acpi_term *
acpi_create_scope_term(
        struct acpi_path *path,
        struct acpi_termlist *termlist)
{
    struct acpi_scope_term *term =
        kmalloc(sizeof(*term), KM_KERNEL);
    if(term == NULL) {
        return NULL;
    }

    term->path = path;
    term->terms = termlist;

    term->term.destroy = __acpi_destroy_scope_term;
    term->term.eval = __acpi_eval_scope_term;
    term->term.dump = __acpi_dump_scope_term;

    return &term->term;
}

