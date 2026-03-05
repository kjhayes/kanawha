
#include <acpi/acpi.h>
#include <acpi/fadt.h>
#include <acpi/table.h>
#include <kanawha/errno.h>
#include <kanawha/init.h>
#include <kanawha/string.h>

static int
acpi_add_fadt_tables(void)
{
    int res;

    printk("Looking for ACPI tables from FADT\n");

    struct acpi_table *fadt_table = acpi_find_table(FADT_SIG_STRING);
    if(fadt_table == NULL)
    {
        wprintk("Failed to find ACPI FADT!\n");
        return 0; // Not a fatal issue
    }
    struct acpi_fadt *fadt = (struct acpi_fadt *)fadt_table->table;
    printk("Found FADT\n");

    {
        void __phys *dsdt_ptr;
        if(fadt->dsdt_xptr != 0)
        {
            printk("Using X_DSDT Pointer!\n");
            dsdt_ptr = (void __phys *)fadt->dsdt_xptr;
        }
        else if(fadt->dsdt_ptr != 0)
        {
            printk("Using DSDT Pointer!\n");
            dsdt_ptr = (void __phys *)(uintptr_t)fadt->dsdt_ptr;
        }
        else
        {
            dsdt_ptr = NULL;
        }

        if(dsdt_ptr != NULL)
        {
            printk("DSDT Physical Address = %p\n", dsdt_ptr);
            struct acpi_table_data *dsdt_table = __va(dsdt_ptr);
            res = acpi_register_raw_table(dsdt_table);
            if(res)
            {
                wprintk("Failed to register ACPI DSDT!\n");
            }
        }
        else
        {
            printk("FADT does not reference DSDT\n");
        }
    }

    {
        void __phys *facs_ptr;
        if(fadt->facs_xptr != 0)
        {
            printk("Using X_FACS Pointer!\n");
            facs_ptr = (void __phys *)fadt->facs_xptr;
        }
        else if(fadt->facs_ptr != 0)
        {
            printk("Using FACS Pointer!\n");
            facs_ptr = (void __phys *)(uintptr_t)fadt->facs_ptr;
        }
        else
        {
            facs_ptr = NULL;
        }

        if(facs_ptr != NULL)
        {
            printk("FACS Physical Address = %p\n", facs_ptr);
            struct acpi_table_data *facs_table = __va(facs_ptr);
            res = acpi_register_raw_table(facs_table);
            if(res)
            {
                wprintk("Failed to register ACPI FACS!\n");
            }
        }
        else
        {
            printk("FADT does not reference FACS\n");
        }
    }

    return 0;
}
declare_init(dynamic, acpi_add_fadt_tables);
