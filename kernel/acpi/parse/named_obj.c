
#include <acpi/parse/named_obj.h>
#include <acpi/parse/opcode.h>
#include <acpi/parse/name.h>
#include <acpi/parse/term.h>
#include <acpi/parse/op_region.h>
#include <acpi/term.h>
#include <acpi/terms/op_region.h>

static struct acpi_term *
acpi_parse_def_bank_field(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefBankField!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_create_bit_field(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefCreateBitField!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_create_byte_field(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefCreateByteField!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_create_dword_field(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefCreateDWordField!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_create_field(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefCreateField!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_create_qword_field(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefCreateQWordField!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_create_word_field(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefCreateWordField!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_data_region(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefDataRegion!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_method(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefMethod!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_mutex(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefMutex!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_device(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefDevice!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_event(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefEvent!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_external(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefExternal!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_power_res(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefPowerRes!\n");
    return NULL;
}
static struct acpi_term *
acpi_parse_def_thermal_zone(struct acpi_parse_ctx *ctx)
{
    wprintk("Cannot parse ACPI DefThermalZone!\n");
    return NULL;
}

int
acpi_parse_named_obj_term(
        struct acpi_parse_ctx *ctx,
        struct acpi_term **term_out)
{
    int res;

    acpi_opcode_t op;
    res = acpi_try_parse_opcode(
            ctx,
            &op);
    if(res) {
        return res;
    }

    struct acpi_term *term = NULL;

    switch(op) {
        case AML_BANK_FIELD_OP:
            term = acpi_parse_def_bank_field(ctx);
            break;
        case AML_CREATE_BIT_FIELD_OP:
            term = acpi_parse_def_create_bit_field(ctx);
            break;
        case AML_CREATE_BYTE_FIELD_OP:
            term = acpi_parse_def_create_byte_field(ctx);
            break;
        case AML_CREATE_DWORD_FIELD_OP:
            term = acpi_parse_def_create_dword_field(ctx);
            break;
        case AML_CREATE_FIELD_OP:
            term = acpi_parse_def_create_field(ctx);
            break;
        case AML_CREATE_QWORD_FIELD_OP:
            term = acpi_parse_def_create_qword_field(ctx);
            break;
        case AML_CREATE_WORD_FIELD_OP:
            term = acpi_parse_def_create_word_field(ctx);
            break;
        case AML_DATA_REGION_OP:
            term = acpi_parse_def_data_region(ctx);
            break;
        case AML_METHOD_OP:
            term = acpi_parse_def_method(ctx);
            break;
        case AML_MUTEX_OP:
            term = acpi_parse_def_mutex(ctx);
            break;
        case AML_DEVICE_OP:
            term = acpi_parse_def_device(ctx);
            break;
        case AML_EVENT_OP:
            term = acpi_parse_def_event(ctx);
            break;
        case AML_EXTERNAL_OP:
            term = acpi_parse_def_external(ctx);
            break;
        case AML_OP_REGION_OP:
            term = acpi_parse_def_op_region(ctx);
            break;
        case AML_OP_REGION_FIELDS_OP:
            term = acpi_parse_def_op_region_fields(ctx);
            break;
        case AML_POWER_RES_OP:
            term = acpi_parse_def_power_res(ctx);
            break;
        case AML_THERMAL_ZONE_OP:
            term = acpi_parse_def_thermal_zone(ctx);
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
