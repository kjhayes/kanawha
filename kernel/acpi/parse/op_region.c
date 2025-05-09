
#include <acpi/parse/op_region.h>
#include <acpi/parse/name.h>
#include <acpi/parse/term.h>
#include <acpi/parse/pkg_length.h>
#include <acpi/terms/op_region.h>

struct acpi_term *
acpi_parse_def_op_region(
        struct acpi_parse_ctx *ctx)
{
    int res;

    struct acpi_path *path;
    res = acpi_parse_name_string(ctx, &path);
    if(res) {
        return NULL;
    }

    uint8_t region_space;
    res = acpi_ctx_pop_u8(ctx, &region_space);
    if(res) {
        acpi_path_destroy(path);
        return NULL;
    }

    struct acpi_term *offset_term;
    res = acpi_try_parse_term_arg(
            ctx,
            &offset_term);
    if(res) {
        acpi_path_destroy(path);
        return NULL;
    }

    struct acpi_term *length_term;
    res = acpi_try_parse_term_arg(
            ctx,
            &length_term);
    if(res) {
        acpi_path_destroy(path);
        acpi_destroy_term(offset_term);
        return NULL;
    }

    struct acpi_term *term;
    term = acpi_create_op_region_term(
            path,
            region_space,
            offset_term,
            length_term);
    if(term == NULL) {
        acpi_path_destroy(path);
        acpi_destroy_term(offset_term);
        acpi_destroy_term(length_term);
        return NULL;

    }

    return term;
}

static int
acpi_parse_op_region_field_flags(
        struct acpi_parse_ctx *ctx,
        struct acpi_op_region_field_flags *flags_out)
{
    int res;
    uint8_t byte;
    res = acpi_ctx_pop_u8(ctx, &byte);
    if(res) {
        return res;
    }

    if(flags_out != NULL) {
        switch(byte & 0xF) {
            case 0:
                flags_out->access_type = ACPI_OP_REGION_FIELD_ACCESS_TYPE_ANY;
                break;
            case 1:
                flags_out->access_type = ACPI_OP_REGION_FIELD_ACCESS_TYPE_BYTE;
                break;
            case 2:
                flags_out->access_type = ACPI_OP_REGION_FIELD_ACCESS_TYPE_WORD;
                break;
            case 3:
                flags_out->access_type = ACPI_OP_REGION_FIELD_ACCESS_TYPE_DWORD;
                break;
            case 4:
                flags_out->access_type = ACPI_OP_REGION_FIELD_ACCESS_TYPE_QWORD;
                break;
            case 5:
                flags_out->access_type = ACPI_OP_REGION_FIELD_ACCESS_TYPE_BUFFER;
                break;
            default:
                flags_out->access_type = ACPI_OP_REGION_FIELD_ACCESS_TYPE_RESERVED;
                break;
        }

        flags_out->locked = ((byte>>4) & 1);

        switch((byte>>5) & 0b11) {
            case 0:
                flags_out->update_rule = ACPI_OP_REGION_FIELD_UPDATE_PRESERVE;
                break;
            case 1:
                flags_out->update_rule = ACPI_OP_REGION_FIELD_UPDATE_WRITE_AS_ONES;
                break;
            case 2:
                flags_out->update_rule = ACPI_OP_REGION_FIELD_UPDATE_WRITE_AS_ZEROS;
                break;
            default:
                flags_out->update_rule = ACPI_OP_REGION_FIELD_UPDATE_RESERVED;
                break;
        }
    }

    return 0;
}

struct acpi_term *
acpi_parse_def_op_region_fields(
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

    struct acpi_op_region_field_flags cur_flags;

    res = acpi_parse_op_region_field_flags(&inner, &cur_flags);
    if(res) {
        acpi_path_destroy(path);
        return NULL;
    }

    struct acpi_op_region_field_list *list;
    list = acpi_create_empty_op_region_field_list();
    if(list == NULL) {
        acpi_path_destroy(path);
        return NULL;
    }

    size_t cur_offset = 0;

    struct acpi_parse_checkpoint chk;
    while(!acpi_ctx_at_end(&inner))
    {
        acpi_ctx_save(&inner, &chk);

        uint8_t byte;
        res = acpi_ctx_pop_u8(ctx, &byte);
        if(res) {
            acpi_path_destroy(path);
            acpi_destroy_op_region_field_list(list);
            return NULL;
        }

        if(byte == 0x00) {
            // Reserved Field
            wprintk("Encountered DefField Reserved Field!\n");
        } else if(byte == 0x01) {
            // Access Field
            wprintk("Encountered DefField Access Field!\n");
        } else if(byte == 0x02) {
            // Connect Field
            wprintk("Encountered DefField Connect Field!\n");
        } else if(byte == 0x03) {
            // Extended Access Field
            wprintk("Encountered DefField Extended Access Field!\n");
        } else {
            acpi_ctx_restore(&inner, &chk);
            struct acpi_op_region_field *field;
            field = acpi_create_blank_op_region_field();
            if(field == NULL) {
                acpi_path_destroy(path);
                acpi_destroy_op_region_field_list(list);
                eprintk("Failed to create a blank ACPI OpRegion field struct!\n");
                return NULL;
            }

            field->flags = cur_flags;
            
            res = acpi_parse_name_segment(
                    &inner,
                    &field->name);
            if(res) {
                acpi_destroy_op_region_field(field);
                acpi_path_destroy(path);
                acpi_destroy_op_region_field_list(list);
                eprintk("Failed to get ACPI OpRegion field name!\n");
                return NULL;
            }

            field->offset = cur_offset;

            uint32_t length;
            res = acpi_parse_pkg_length(&inner, &length);
            if(res) {
                acpi_destroy_op_region_field(field);
                acpi_path_destroy(path);
                acpi_destroy_op_region_field_list(list);
                eprintk("Failed to get ACPI OpRegion field length!\n");
                return NULL;
            }

            field->length = length;

            cur_offset += length;

            res = acpi_op_region_field_list_append(list, field);
            if(res) {
                acpi_destroy_op_region_field(field);
                acpi_path_destroy(path);
                acpi_destroy_op_region_field_list(list);
                eprintk("Failed to append ACPI OpRegion field!\n");
                return NULL;
            }
        }
    }

    struct acpi_term *term;
    term = acpi_create_op_region_fields_term(
            path,
            list);
    if(term == NULL) {
        acpi_path_destroy(path);
        acpi_destroy_op_region_field_list(list);
        eprintk("Failed to create ACPI OpRegion field term!\n");
        return NULL;
    }

    return term;
}

