#ifndef __KANAWHA__ACPI_ACPI_H__
#define __KANAWHA__ACPI_ACPI_H__

#include <acpi/table.h>

int
acpi_provide_rsdp(struct acpi_rsdp *rsdp);
int
acpi_provide_xsdp(struct acpi_xsdp *xsdp);

struct acpi_table_hdr *
acpi_find_table(const char *signature);

uint32_t acpi_revision(void);

#endif
