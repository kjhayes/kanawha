
#include <acpi/parse/ctx.h>
#include <acpi/parse/target.h>
#include <acpi/parse/term.h>
#include <acpi/parse/opcode.h>
#include <acpi/parse/name.h>
#include <acpi/target.h>

#include <kanawha/errno.h>

int
acpi_parse_target(
        struct acpi_parse_ctx *ctx,
        struct acpi_target **target_out)
{
    int res;

    struct acpi_parse_checkpoint chk;
    acpi_ctx_save(ctx, &chk);

    acpi_opcode_t opcode;
    res = acpi_try_parse_opcode(ctx, &opcode);
    if(res == 0) {

        struct acpi_target *target;

        switch(opcode) {
            case AML_ZERO_OP:
                if(target_out) {
                    *target_out = acpi_create_null_target();
                    if(*target_out == NULL) {
                        return -ENOMEM;
                    }
                }
                return 0;
            case AML_DEBUG_OP:
                if(target_out) { 
                    *target_out = acpi_create_debug_target();
                    if(*target_out == NULL) {
                        return -ENOMEM;
                    }
                }
                return 0;
            default:
                break;
        }

    }
    acpi_ctx_restore(ctx, &chk);

    struct acpi_path *path;
    res = acpi_parse_name_string(ctx, &path);
    if(res == 0) {
        if(*target_out) {
            *target_out = acpi_create_named_target(path);
            if(*target_out == NULL) {
                acpi_path_destroy(path);
                return -ENOMEM;
            }
        } else {
            acpi_path_destroy(path);
        }
        return 0;
    }
    acpi_ctx_restore(ctx, &chk);

    struct acpi_term *term;
    res = acpi_try_parse_term_arg(ctx, &term);
    if(res) {
        wprintk("acpi_parse_target: Failed to parse term target! (err=%s)\n",
                errnostr(res));
        return res;
    }

    if(target_out != NULL) {
        struct acpi_target *target = acpi_create_term_target(term);
        if(target == NULL) {
            acpi_destroy_term(term);
            return -ENOMEM;
        }
        *target_out = target;
        return 0;
    }
    acpi_destroy_term(term);
    return 0;
}

