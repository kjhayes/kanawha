
#include <acpi/terms/method.h>

#include <kanawha/stddef.h>
#include <kanawha/kmalloc.h>

struct acpi_method_invocation_term {
    struct acpi_term term;
    struct acpi_path *method_name;
    struct acpi_termlist *arg_terms;
};

static int
__acpi_destroy_method_invocation_term(
        struct acpi_term *term)
{
    struct acpi_method_invocation_term *iterm =
        container_of(term, struct acpi_method_invocation_term, term);

    acpi_path_destroy(iterm->method_name);
    acpi_destroy_termlist(iterm->arg_terms);
    kfree(term);

    return 0;
}

static int
__acpi_eval_method_invocation_term(
        struct acpi_term *term,
        struct acpi_eval_ctx *ctx,
        struct acpi_obj **obj_out)
{
    wprintk("ACPI tried to evaluate method invocation term!\n");
    return -EUNIMPL;
}

static int
__acpi_dump_method_invocation_term(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    struct acpi_method_invocation_term *iterm =
        container_of(term, struct acpi_method_invocation_term, term);
    acpi_dump_term_indent(printer, depth);
    (*printer)("METHOD-CALL(");
    acpi_dump_path(printer, iterm->method_name);
    (*printer)(")\n");
    acpi_dump_termlist(
            iterm->arg_terms,
            printer,
            depth);
    return 0;
}
struct acpi_term *
acpi_create_method_invocation_term(
        struct acpi_path *method_name,
        struct acpi_termlist *terms)
{
    struct acpi_method_invocation_term *iterm =
        kmalloc(sizeof(*iterm));
    if(iterm == NULL) {
        return NULL;
    }
    iterm->arg_terms = terms;
    iterm->method_name = method_name;

    iterm->term.destroy = __acpi_destroy_method_invocation_term;
    iterm->term.eval = __acpi_eval_method_invocation_term;
    iterm->term.dump = __acpi_dump_method_invocation_term;

    return &iterm->term;
}
