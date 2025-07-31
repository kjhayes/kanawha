
#include <acpi/terms/op_region.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>

struct acpi_op_region_term {
    struct acpi_term term;
    struct acpi_path *path;
    uint8_t region_space;
    struct acpi_term *offset;
    struct acpi_term *length;
};

static int
__acpi_destroy_op_region_term(
        struct acpi_term *term)
{
    struct acpi_op_region_term *oterm =
        container_of(term, struct acpi_op_region_term, term);

    acpi_destroy_term(oterm->offset);
    acpi_destroy_term(oterm->length);
    acpi_path_destroy(oterm->path);
    kfree(oterm);

    return 0;
}

static int
__acpi_dump_op_region_term(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    struct acpi_op_region_term *oterm =
        container_of(term, struct acpi_op_region_term, term);

    acpi_dump_term_indent(printer, depth);
    (*printer)("OP-REGION(");
    acpi_dump_path(printer, oterm->path);
    (*printer)(", ");

    switch(oterm->region_space) {
        case 0x01: (*printer)("SystemIO"); break;
        case 0x02: (*printer)("PCI_Config"); break;
        case 0x03: (*printer)("EmbeddedControl"); break;
        case 0x04: (*printer)("SMBus"); break;
        case 0x05: (*printer)("System CMOS"); break;
        case 0x06: (*printer)("PciBarTarget"); break;
        case 0x07: (*printer)("IPMI"); break;
        case 0x08: (*printer)("GeneralPurposeIO"); break;
        case 0x09: (*printer)("GenericSerialBus"); break;
        case 0x0A: (*printer)("PCC"); break;
        default: (*printer)("OEM Defined"); break;
    }

    (*printer)(",\n");

    acpi_dump_term_indent(printer, depth+1);
    (*printer)("OFFSET=\n");
    acpi_dump_term(oterm->offset, printer, depth+1);
    acpi_dump_term_indent(printer, depth+1);
    (*printer)("LENGTH=\n");
    acpi_dump_term(oterm->length, printer, depth+1);

    acpi_dump_term_indent(printer, depth);
    (*printer)(")\n");

    return 0;
}

static int
__acpi_eval_op_region_term(
        struct acpi_term *term,
        struct acpi_eval_ctx *ctx,
        struct acpi_obj **obj_out)
{
    wprintk("Tried to eval ACPI op region term!\n");
    return -EUNIMPL;
}

struct acpi_term *
acpi_create_op_region_term(
        struct acpi_path *path,
        uint8_t region_space,
        struct acpi_term *offset_term,
        struct acpi_term *length_term)
{
    struct acpi_op_region_term *term =
        kmalloc(sizeof(*term), KM_KERNEL);
    if(term == NULL) {
        return NULL;
    }

    term->path = path;
    term->region_space = region_space;
    term->offset = offset_term;
    term->length = length_term;

    term->term.destroy = __acpi_destroy_op_region_term;
    term->term.eval = __acpi_eval_op_region_term;
    term->term.dump = __acpi_dump_op_region_term;

    return &term->term;
}

struct acpi_op_region_fields_term {
    struct acpi_term term;
    struct acpi_path *path;
    struct acpi_op_region_field_list *field_list;
};

static int
__acpi_dump_op_region_fields_term(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    struct acpi_op_region_fields_term *rterm =
        container_of(term, struct acpi_op_region_fields_term, term);

    acpi_dump_term_indent(printer, depth);
    (*printer)("OP-REGION-FIELDS(");
    acpi_dump_path(printer, rterm->path);
    (*printer)(", {\n");
    ilist_node_t *node;
    ilist_for_each(node, &rterm->field_list->field_list) {
        struct acpi_op_region_field *field =
            container_of(node, struct acpi_op_region_field, list_node);
        acpi_dump_term_indent(printer, depth+1);
        (*printer)("FIELD(");
        acpi_dump_name(printer, &field->name);
        (*printer)(", offset=0x%lx, length=0x%x, access_type=%s, lock=%s, update_rule=%s)\n",
                field->offset,
                field->length,
                field->flags.access_type == ACPI_OP_REGION_FIELD_ACCESS_TYPE_ANY    ? "ANY" :
                field->flags.access_type == ACPI_OP_REGION_FIELD_ACCESS_TYPE_BYTE   ? "BYTE" :
                field->flags.access_type == ACPI_OP_REGION_FIELD_ACCESS_TYPE_WORD   ? "WORD" :
                field->flags.access_type == ACPI_OP_REGION_FIELD_ACCESS_TYPE_DWORD  ? "DWORD" :
                field->flags.access_type == ACPI_OP_REGION_FIELD_ACCESS_TYPE_QWORD  ? "QWORD" :
                field->flags.access_type == ACPI_OP_REGION_FIELD_ACCESS_TYPE_BUFFER ? "BUFFER" :
                "RESERVED",
                field->flags.locked ? "YES" : "NO",
                field->flags.update_rule == ACPI_OP_REGION_FIELD_UPDATE_PRESERVE ? "PRESERVE" :
                field->flags.update_rule == ACPI_OP_REGION_FIELD_UPDATE_WRITE_AS_ZEROS ? "WRITE_ZEROS" :
                field->flags.update_rule == ACPI_OP_REGION_FIELD_UPDATE_WRITE_AS_ONES ? "WRITE_ONES" :
                "RESERVED" 
                );
    }
    acpi_dump_term_indent(printer, depth);
    (*printer)("})\n");
    return 0;
}

static int
__acpi_eval_op_region_fields_term(
        struct acpi_term *term,
        struct acpi_eval_ctx *ctx,
        struct acpi_obj **obj_out)
{
    wprintk("Tried to evaluate ACPI DefField!\n");
    return -EUNIMPL;
}

static int
__acpi_destroy_op_region_fields_term(
        struct acpi_term *term)
{
    struct acpi_op_region_fields_term *rterm =
        container_of(term, struct acpi_op_region_fields_term, term);

    acpi_destroy_op_region_field_list(rterm->field_list);
    acpi_path_destroy(rterm->path);
    kfree(rterm);

    return 0;
}

struct acpi_term *
acpi_create_op_region_fields_term(
        struct acpi_path *path,
        struct acpi_op_region_field_list *field_list)
{
    struct acpi_op_region_fields_term *term;
    term = kmalloc(sizeof(*term), KM_KERNEL);
    if(term == NULL) {
        return NULL;
    }

    term->path = path;
    term->field_list = field_list;

    term->term.dump = __acpi_dump_op_region_fields_term;
    term->term.eval = __acpi_eval_op_region_fields_term;
    term->term.destroy = __acpi_destroy_op_region_fields_term;

    return &term->term;
}

struct acpi_op_region_field *
acpi_create_blank_op_region_field(void)
{
    struct acpi_op_region_field *field;
    field = kmalloc(sizeof(*field), KM_KERNEL);
    if(field == NULL) {
        return NULL;
    }
    field->name.value = 0x0;
    field->length = 0x0;
    field->offset = 0x0;
    field->flags.locked = 0;
    field->flags.access_type = ACPI_OP_REGION_FIELD_ACCESS_TYPE_RESERVED;
    field->flags.update_rule = ACPI_OP_REGION_FIELD_UPDATE_RESERVED;

    return field;
}

int
acpi_destroy_op_region_field(
        struct acpi_op_region_field *field)
{
    kfree(field);
    return 0;
}

struct acpi_op_region_field_list *
acpi_create_empty_op_region_field_list(void)
{
    struct acpi_op_region_field_list *list;
    list = kmalloc(sizeof(*list), KM_KERNEL);
    if(list == NULL) {
        return NULL;
    }
    ilist_init(&list->field_list);

    return list;
}

int
acpi_destroy_op_region_field_list(
        struct acpi_op_region_field_list *list)
{
    ilist_node_t *node = ilist_pop_tail(&list->field_list);

    while(node) {
        struct acpi_op_region_field *field
            = container_of(node, struct acpi_op_region_field, list_node);
        acpi_destroy_op_region_field(field);
        node = ilist_pop_tail(&list->field_list);
    }

    kfree(list);
    return 0;
}

int
acpi_op_region_field_list_append(
        struct acpi_op_region_field_list *list,
        struct acpi_op_region_field *field)
{
    ilist_push_tail(
            &list->field_list,
            &field->list_node);
    return 0;
}

