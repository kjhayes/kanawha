
#include <acpi/parse/ctx.h>
#include <acpi/parse/name.h>
#include <acpi/parse/opcode.h>

#include <kanawha/errno.h>

int
acpi_parse_name_segment(
        struct acpi_parse_ctx *ctx,
        struct acpi_name *name_out)
{
    int res;

    struct acpi_name name;

    res = acpi_ctx_pop_u32(ctx, &name.value);
    if(res) {
        return res;
    }

    res = acpi_verify_name(&name);
    if(res) {
        return res;
    }

    if(name_out) {
        *name_out = name;
    }

    return 0;
}

int
acpi_parse_name_string(
        struct acpi_parse_ctx *ctx,
        struct acpi_path **path_out)
{
    int res;

    int prefixes = 0;

    struct acpi_parse_checkpoint chk;
    acpi_ctx_save(ctx, &chk);

    uint8_t byte;
    res = acpi_ctx_pop_u8(ctx, &byte);
    if(res) {
        return res;
    }

    // Determine Prefixes
    switch(byte) {
        case AML_ROOT_CHAR:
            prefixes = ACPI_PATH_PARENT_PREFIX_ABSOLUTE;
            break;
        case AML_PARENT_PREFIX_OP:
            while(1) {
                prefixes++;
                acpi_ctx_save(ctx, &chk);
                res = acpi_ctx_pop_u8(ctx, &byte);
                if(res) {
                    return res;
                }
                if(byte != AML_PARENT_PREFIX_OP) {
                    acpi_ctx_restore(ctx, &chk);
                    break;
                }
            }
            break;
        default:
            acpi_ctx_restore(ctx, &chk);
            break;
    }

    size_t pathlen = 1;

    acpi_ctx_save(ctx, &chk);
    res = acpi_ctx_pop_u8(ctx, &byte);
    if(res) {
        return res;
    }

    switch(byte) {
        case 0x00:
            pathlen = 0;
            break;
        case AML_DUAL_NAME_PREFIX:
            pathlen = 2;
            break;
        case AML_MULTI_NAME_PREFIX:
            res = acpi_ctx_pop_u8(ctx, &byte);
            pathlen = byte;
            break;
        default:
            acpi_ctx_restore(ctx, &chk);
            break;
    }

    struct acpi_path *path = acpi_path_create(pathlen, prefixes);
    if(path == NULL) {
        return -ENOMEM;
    }

    for(size_t i = 0; i < pathlen; i++) {
        struct acpi_name *name = &path->names[i];
        res = acpi_parse_name_segment(ctx, name);
        if(res) {
            return res;
        }
    }

    if(path_out != NULL) {
        *path_out = path;
    } else {
        acpi_path_destroy(path);
    }

    return 0;
}

