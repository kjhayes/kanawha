
#include <acpi/parse/namespace_modifier.h>
#include <acpi/parse/opcode.h>
#include <acpi/parse/name.h>
#include <acpi/parse/term.h>
#include <acpi/parse/pkg_length.h>
#include <acpi/name.h>
#include <acpi/terms/namespace_modifier.h>

static struct acpi_term *
acpi_parse_def_alias(
        struct acpi_parse_ctx *ctx)
{
    wprintk("ACPI AML: Cannot parse DefAliasOp!\n");
    return NULL;
}

static struct acpi_term *
acpi_parse_def_name(
        struct acpi_parse_ctx *ctx)
{
    wprintk("ACPI AML: Cannot parse DefNameOp!\n");
    return NULL;
}

static struct acpi_term *
acpi_parse_def_scope(
        struct acpi_parse_ctx *ctx)
{
    int res;

    struct acpi_parse_ctx inner;

    res = acpi_segment_package(ctx, &inner);
    if(res) {
        return NULL;
    }

    struct acpi_path *path;
    res = acpi_parse_name_string(&inner, &path);
    if(res) {
        return NULL;
    }

    struct acpi_termlist *termlist = acpi_create_empty_termlist();
    if(termlist == NULL) {
        acpi_path_destroy(path);
        return NULL;
    }

    res = acpi_populate_termlist(
            &inner,
            termlist
            );
    if(res) {
        return NULL;
    }

    struct acpi_term *term =
        acpi_create_scope_term(
            path,
            termlist);
    if(term == NULL) {
        acpi_path_destroy(path);
        acpi_destroy_termlist(termlist);
        return NULL;
    }

    return term;
}

int
acpi_parse_namespace_modifier_term(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out)
{
    int res;

    acpi_opcode_t op;

    res = acpi_try_parse_opcode(ctx, &op);
    if(res) {
        return res;
    }

    struct acpi_term *term = NULL;

    switch(op) {
        case AML_ALIAS_OP:
            term = acpi_parse_def_alias(ctx);
            break;
        case AML_NAME_OP:
            term = acpi_parse_def_name(ctx);
            break;
        case AML_SCOPE_OP:
            term = acpi_parse_def_scope(ctx);
            break;
        default:
            return -EINVAL;
    }

    if(term == NULL) {
        return -EINVAL;
    }

    if(term_out != NULL) {
        *term_out = term;
    }

    return 0;
}

