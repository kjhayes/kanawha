
#include <acpi/namespace.h>
#include <acpi/acpi.h>
#include <acpi/table.h>
#include <acpi/interp.h>

#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>

static int
acpi_load_aml_into_namespace(
	void *aml_data,
	size_t aml_len)
{
    int res;

    struct acpi_namespace *ns = acpi_default_namespace();
    if(ns == NULL) {
	wprintk("Could not find ACPI default namespace: Failing to load AML table!\n");
	return -EDEFER;
    }

    struct acpi_node *scope = acpi_namespace_get_root(ns);

    res = acpi_interpret_aml(
	    scope,
	    aml_data,
	    aml_len);
    if(res) {
        acpi_namespace_dump(do_printk, ns);
	eprintk("Failed to interpret AML from DSDT! (err=%s)\n", errnostr(res));
	return res;
    }

    acpi_node_put(scope);

    return 0;
}

static int
acpi_load_dsdt_into_namespace(void)
{
    int res;

    struct acpi_table *dsdt = acpi_find_table("DSDT");
    if(dsdt == NULL) {
        wprintk("Could not find ACPI DSDT: Failing to load DSDT!\n");
	return -EDEFER;
    }

    struct acpi_table_data *dsdt_data = (struct acpi_table_data*)dsdt->table;

    void *aml_data = dsdt_data->data;
    size_t aml_len = dsdt_data->hdr.length - sizeof(struct acpi_table_hdr);

    res = acpi_load_aml_into_namespace(
	    aml_data,
	    aml_len);
    if(res) {
	wprintk("Failed to load DSDT AML into ACPI namespace! (Continuing)\n");
	return 0;
    }

    return 0;
}
declare_init_desc(bus, acpi_load_dsdt_into_namespace, "Loading ACPI DSDT into Namespace");

