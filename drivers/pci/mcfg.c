
#include <kanawha/init.h>
#include <kanawha/string.h>
#include <kanawha/errno.h>
#include <kanawha/kmalloc.h>
#include <acpi/acpi.h>
#include <acpi/table.h>
#include <drivers/pci/mmio_ecam.h>
#include <drivers/pci/cfg.h>

#define MCFG_SIG_STRING "MCFG"

struct __packed acpi_mcfg_entry {
    uint64_t base_addr;
    uint16_t segment;
    uint8_t start_bus;
    uint8_t end_bus;
    uint32_t reserved;
};

ASSERT_TYPE_SIZE(struct acpi_mcfg_entry, 16);

static int
pcie_acpi_probe_mcfg_table(void)
{
    int res;

    struct acpi_table *mcfg_table = acpi_find_table(MCFG_SIG_STRING);
    if(mcfg_table == NULL) {
        dprintk("Failed to find ACPI MCFG for PCIe!\n");
        return 0; // Not a fatal issue
    }

    struct acpi_table_data *mcfg = mcfg_table->table;

    size_t datalen = acpi_table_get_data_len(mcfg);
    void *data = acpi_table_get_data_ptr(mcfg);

    // First 8 bytes are reserved
    datalen -= 8;
    data += 8;

    size_t num_entries = datalen / sizeof(struct acpi_mcfg_entry);
    struct acpi_mcfg_entry *entries = data;

    for(size_t i = 0; i < num_entries; i++) {
        struct acpi_mcfg_entry *cur = &entries[i];

        dprintk("MCFG Entry: base=%p, segment=0x%lx, start_bus=0x%x, end_bus=0x%x\n",
                cur->base_addr,
                (ul_t)cur->segment,
                cur->start_bus,
                cur->end_bus);

        struct mmio_pci_ecam *ecam = kmalloc(sizeof(struct mmio_pci_ecam), KM_KERNEL);
        if(ecam == NULL) {
            wprintk("Failed to allocate struct for MCFG PCIe ECAM!\n");
            break;
        }

        res = register_mmio_pci_ecam(
                ecam,
                cur->segment,
                (void __phys *)cur->base_addr,
                pci_mmio_ecam_size_for_n_buses(cur->end_bus+1));
        if(res) {
            kfree(ecam);
        }

        // NOTE: We leak the "ecam" struct here.

        res = pci_probe_segment_with_assumed_buses(
                cur->segment,
                cur->start_bus,
                (cur->end_bus - cur->start_bus) + 1);
        if(res) {
            wprintk("Failed to probe buses specified by MCFG PCIe!\n");
        }
    }

    return 0;
}

declare_init_desc(bus, pcie_acpi_probe_mcfg_table, "Looking for ACPI MCFG Table for PCIe");

