
#include <acpi/namespace.h>
#include <acpi/acpi.h>
#include <acpi/table.h>
#include <acpi/term.h>
#include <acpi/parse/term.h>

#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>

static int
acpi_load_namespace(void)
{
    int res;

    struct acpi_table *dsdt = acpi_find_table("DSDT");
    if(dsdt == NULL) {
        wprintk("Could not find ACPI DSDT: Failing to load ACPI namespace!\n");
        return 0; // Not a fatal error
    }
    struct acpi_table_data *dsdt_data = (struct acpi_table_data*)dsdt->table;

    void *aml_data = dsdt_data->data;
    size_t aml_len = dsdt_data->hdr.length - sizeof(struct acpi_table_hdr);

    struct acpi_parse_ctx dsdt_ctx;
    res = acpi_init_parse_ctx(
            &dsdt_ctx,
            aml_data,
            aml_len);
    if(res) {
        return res;
    }

    struct acpi_termlist *dsdt_termlist;
    dsdt_termlist = acpi_create_empty_termlist();
    if(dsdt_termlist == NULL) {
        return -ENOMEM;
    }

    res = acpi_populate_termlist(
            &dsdt_ctx,
            dsdt_termlist); 
    if(res) {
        eprintk("Failed to parse AML code in DSDT!\n");
        return res;
    }

    if(!acpi_ctx_at_end(&dsdt_ctx)) {
        wprintk("Failed to parse entire DSDT! (Ignoring...)\n");
    }

    printk("Parsed DSDT:\n");
    acpi_dump_termlist(dsdt_termlist, do_printk, 0);

    // TODO exec the code to generate the namespace

    acpi_destroy_termlist(dsdt_termlist);

    return 0;
}
//declare_init_desc(bus, acpi_load_namespace, "Loading ACPI Namespace");

