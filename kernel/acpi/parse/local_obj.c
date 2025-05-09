
#include <acpi/parse/data_obj.h>
#include <acpi/parse/ctx.h>
#include <acpi/parse/opcode.h>
#include <acpi/terms/local_obj.h>
#include <acpi/term.h>

#include <kanawha/kmalloc.h>


int
acpi_parse_arg_obj(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out)
{
    int res;

    acpi_opcode_t opcode;
    res = acpi_try_parse_opcode(ctx, &opcode);
    if(res) {
        return res;
    }

    size_t index;

    switch(opcode) {
        case AML_ARG_0_OP:
            index = 0;
            break;
        case AML_ARG_1_OP:
            index = 1;
            break;
        case AML_ARG_2_OP:
            index = 2;
            break;
        case AML_ARG_3_OP:
            index = 3;
            break;
        case AML_ARG_4_OP:
            index = 4;
            break;
        case AML_ARG_5_OP:
            index = 5;
            break;
        case AML_ARG_6_OP:
            index = 6;
            break;
        default:
            return -EINVAL;
    }

    if(term_out != NULL) {
        struct acpi_term *term = acpi_create_arg_term(index);
        if(term == NULL) {
            return -ENOMEM;
        }
        *term_out = term;
    }

    return 0;
}

int
acpi_parse_local_obj(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out)
{
    int res;

    acpi_opcode_t opcode;
    res = acpi_try_parse_opcode(ctx, &opcode);
    if(res) {
        return res;
    }

    size_t index;

    switch(opcode) {
        case AML_LOCAL_0_OP:
            index = 0;
            break;
        case AML_LOCAL_1_OP:
            index = 1;
            break;
        case AML_LOCAL_2_OP:
            index = 2;
            break;
        case AML_LOCAL_3_OP:
            index = 3;
            break;
        case AML_LOCAL_4_OP:
            index = 4;
            break;
        case AML_LOCAL_5_OP:
            index = 5;
            break;
        case AML_LOCAL_6_OP:
            index = 6;
            break;
        case AML_LOCAL_7_OP:
            index = 7;
            break;
        default:
            return -EINVAL;
    }

    if(term_out != NULL) {
        struct acpi_term *term = acpi_create_local_term(index);
        if(term == NULL) {
            return -ENOMEM;
        }
        *term_out = term;
    }

    return 0;
}

