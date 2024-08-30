
#include <acpi/acpi.h>
#include <mb2/info.h>
#include <kanawha/printk.h>
#include <kanawha/errno.h>
#include <kanawha/init.h>
#include <kanawha/vmem.h>

#define MULTIBOOT2_INFO_TAG_RSDP_v1 14
#define MULTIBOOT2_INFO_TAG_RSDP_v2 15

static void
mb2_rsdp_handler(
        struct mb2_info *info,
        struct mb2_info_tag *tag,
        void *state)
{
    int *res = state;
    if(*res) {
        return;
    }

    if(tag->hdr.type == MULTIBOOT2_INFO_TAG_RSDP_v1) {
        printk("Found ACPI RSDP in Mutliboot2 Info\n");
        struct acpi_rsdp *rsdp = ((void*)tag) + sizeof(struct mb2_info_tag_header);
        *res = acpi_provide_rsdp(rsdp);
        return;
    }

    if(tag->hdr.type == MULTIBOOT2_INFO_TAG_RSDP_v2) {
        printk("Found ACPI XSDP in Multiboot2 Info!\n");
        struct acpi_xsdp *xsdp = ((void*)tag) + sizeof(struct mb2_info_tag_header);
        *res = acpi_provide_xsdp(xsdp);
        return;
    }
}
 
static int
mb2_find_acpi_rsdp(void)
{
    int res = 0;
    mb2_info_for_each_tag(
            boot_mb2_info_ptr,
            mb2_rsdp_handler,
            &res);
    return res;
}
declare_init_desc(boot, mb2_find_acpi_rsdp, "Search Multiboot2 Info for ACPI RSDP");

