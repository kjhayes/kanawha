
#include <acpi/parse/term.h>
#include <acpi/parse/opcode.h>
#include <acpi/parse/data_obj.h>
#include <acpi/parse/local_obj.h>
#include <acpi/parse/expression.h>
#include <acpi/parse/statement.h>
#include <acpi/parse/named_obj.h>
#include <acpi/parse/namespace_modifier.h>

int
acpi_try_parse_term_obj(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out
        )
{
    int res;

    struct acpi_parse_checkpoint chk;
    acpi_ctx_save(ctx, &chk);
 
    res = acpi_parse_statement_term(ctx, term_out);
    if(res == 0) {
        return 0;
    }
    acpi_ctx_restore(ctx, &chk);

    res = acpi_parse_expression_term(ctx, term_out);
    if(res == 0) {
        return 0;
    }
    acpi_ctx_restore(ctx, &chk);

    res = acpi_parse_named_obj_term(ctx, term_out);
    if(res == 0) {
        return 0;
    }
    acpi_ctx_restore(ctx, &chk);

    res = acpi_parse_namespace_modifier_term(ctx, term_out);
    if(res == 0) {
        return 0;
    }
    acpi_ctx_restore(ctx, &chk);

    // Log why we failed with a warning
    acpi_opcode_t op;
    res = acpi_try_parse_opcode(ctx, &op);
    if(res) {
        wprintk("acpi_try_parse_term_obj: Failed to parse opcode!\n");
    } else {
        wprintk("acpi_try_parse_term_obj: Failed to parse opcode: (%s)\n",
                acpi_opcode_to_string(op));
        acpi_ctx_restore(ctx, &chk);
    }

    return -EINVAL;
}


int
acpi_try_parse_term_arg(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out)
{
    int res;

    res = acpi_try_parse_data_obj(ctx, term_out);
    if(res == 0) {
        return res;
    }
 
    struct acpi_parse_checkpoint chk;
    acpi_ctx_save(ctx, &chk);

    res = acpi_parse_arg_obj(ctx, term_out);
    if(res == 0) {
        return 0;
    }
    acpi_ctx_restore(ctx, &chk);

    res = acpi_parse_local_obj(ctx, term_out);
    if(res == 0) {
        return 0;
    }
    acpi_ctx_restore(ctx, &chk);

    res = acpi_parse_expression_term(ctx, term_out);
    if(res == 0) {
        return 0;
    }
    acpi_ctx_restore(ctx, &chk);

    // Log why we failed with a warning
    acpi_opcode_t op;
    res = acpi_try_parse_opcode(ctx, &op);
    if(res) {
        wprintk("acpi_try_parse_term_arg: Failed to parse opcode!\n");
    } else {
        wprintk("acpi_try_parse_term_arg: Failed to parse opcode: (%s)\n",
                acpi_opcode_to_string(op));
        acpi_ctx_restore(ctx, &chk);
    }

    return -EINVAL;
}

int
acpi_populate_termlist(
        struct acpi_parse_ctx *ctx,
        struct acpi_termlist *list)
{
    int res;

    while(!acpi_ctx_at_end(ctx))
    {
        struct acpi_term *term;
        res = acpi_try_parse_term_obj(
                ctx,
                &term);
        if(res) {
            break;
        }

        res = acpi_termlist_append(
                list,
                term);
        if(res) {
            break;
        }
    }

    if(!acpi_ctx_at_end(ctx)) {
        acpi_opcode_t op;
        acpi_try_parse_opcode(ctx, &op);
        wprintk("FAILED TO PARSE FULL TERMLIST! (next_op=%s)\n",
                acpi_opcode_to_string(op));
        //return -EINVAL;
    }

    return 0;
}

int
acpi_populate_arg_termlist(
        struct acpi_parse_ctx *ctx,
        struct acpi_termlist *list)
{
    int res;

    while(!acpi_ctx_at_end(ctx))
    {
        struct acpi_term *term;
        res = acpi_try_parse_term_arg(
                ctx,
                &term);
        if(res) {
            break;
        }

        res = acpi_termlist_append(
                list,
                term);
        if(res) {
            break;
        }
    }

//    if(!acpi_ctx_at_end(ctx)) {
//        acpi_opcode_t op;
//        acpi_try_parse_opcode(ctx, &op);
//        wprintk("FAILED TO PARSE FULL TERMLIST! (next_op=%s)\n",
//                acpi_opcode_to_string(op));
//        //return -EINVAL;
//    }

    return 0;
}

