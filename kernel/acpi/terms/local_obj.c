
#include <acpi/terms/local_obj.h>
#include <acpi/term.h>
#include <kanawha/types.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>

static int
__destroy_local_term(
        struct acpi_term *term)
{
    kfree(term);
    return 0;
}

static struct acpi_term *
__create_local_term(void)
{
    struct acpi_term *term =
        kmalloc(sizeof(struct acpi_term));
    if(term == NULL) {
        return NULL;
    }
    memset(term, 0, sizeof(*term));

    term->destroy = __destroy_local_term;

    return term;
}

static int
__dump_arg_term(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    acpi_dump_term_indent(printer, depth);
    (*printer)("ARG(%d)\n", (int)term->priv.value);
    return 0;
}
static int
__dump_local_term(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    acpi_dump_term_indent(printer, depth);
    (*printer)("ARG(%d)\n", (int)term->priv.value);
    return 0;
}

static int
__eval_arg_term(
        struct acpi_term *term,
        struct acpi_eval_ctx *ctx,
        struct acpi_obj **obj)
{
    wprintk("Trying to evaluate ACPI argument term!\n");
    return -EUNIMPL;
}

static int
__eval_local_term(
        struct acpi_term *term,
        struct acpi_eval_ctx *ctx,
        struct acpi_obj **obj)
{
    wprintk("Trying to evaluate ACPI local term!\n");
    return -EUNIMPL;
}

struct acpi_term *
acpi_create_arg_term(size_t index)
{
    if(index > 6) {
        return NULL;
    }
    struct acpi_term *term;
    term = __create_local_term();

    term->priv.value = index;
    term->eval = __eval_arg_term;
    term->dump = __dump_arg_term;

    return term;
}

struct acpi_term *
acpi_create_local_term(size_t index)
{
    if(index > 7) {
        return NULL;
    }
    struct acpi_term *term;

    term = __create_local_term();

    term->priv.value = index;
    term->eval = __eval_local_term;
    term->dump = __dump_local_term;

    return term;
}

