
#include <acpi/name.h>
#include <acpi/parse/invoke.h>
#include <acpi/parse/term.h>
#include <acpi/parse/name.h>
#include <acpi/terms/method.h>

int
acpi_parse_method_invocation_term(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out)
{
    int res;

    struct acpi_path *path;
    res = acpi_parse_name_string(
            ctx,
            &path);
    if(res) {
        return res;
    }

    printk("Method Invokation: \"");
    acpi_dump_path(do_printk, path);
    printk("\"\n");

    struct acpi_termlist *terms;
    terms = acpi_create_empty_termlist();

    res = acpi_populate_arg_termlist(ctx, terms);
    if(res) {
        acpi_path_destroy(path);
        return res;
    }

    if(term_out != NULL) {
        struct acpi_term *term;
        term = acpi_create_method_invocation_term(
                path,
                terms);
        if(term == NULL) {
            acpi_destroy_termlist(terms);
            acpi_path_destroy(path);
            return -ENOMEM;
        }
        *term_out = term;
    } else {
        acpi_destroy_termlist(terms);
        acpi_path_destroy(path);
    }

    return 0;
}

