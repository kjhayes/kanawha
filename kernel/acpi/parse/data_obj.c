
#include <acpi/parse/data_obj.h>
#include <acpi/parse/constants.h>

int
acpi_try_parse_data_obj(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out)
{
    int res;

    struct acpi_parse_checkpoint chk;
    acpi_ctx_save(ctx, &chk);

    res = acpi_try_parse_computational_data(
            ctx,
            term_out);
    if(res == 0) {
        return 0;
    }
    acpi_ctx_restore(ctx, &chk);

    wprintk("Incomplete acpi_try_parse_data_obj\n");

//    res = acpi_parse_def_package(
//            ctx,
//            term_out);
//    if(res == 0) {
//        return 0;
//    }
//    acpi_ctx_restore(ctx, &chk);
//
//    res = acpi_parse_def_var_package(
//            ctx,
//            term_out);
//    if(res == 0) {
//        return 0;
//    }
//    acpi_ctx_restore(ctx, &chk);

    return -EINVAL;
}


int
acpi_try_parse_computational_data(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out)
{
    int res;

    struct acpi_parse_checkpoint chk;
    acpi_ctx_save(ctx, &chk);

    res = acpi_parse_integer_const(
            ctx,
            term_out);
    if(res == 0) {
        return 0;
    }
    acpi_ctx_restore(ctx, &chk);

    res = acpi_parse_string_const(
            ctx,
            term_out);
    if(res == 0) {
        return 0;
    }
    acpi_ctx_restore(ctx, &chk);

    wprintk("Incomplete acpi_try_parse_computational_data\n");

//    res = acpi_parse_def_buffer(
//            ctx,
//            term_out);
//    if(res == 0) {
//        return 0;
//    }
//    acpi_ctx_restore(ctx, &chk);

    return -EINVAL;
}


