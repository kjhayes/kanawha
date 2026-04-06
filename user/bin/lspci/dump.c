
#include <errno.h>
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>
#include <stdio.h>
#include <stdlib.h>
#include "pciids.h"

struct pci_config_space
{
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t command;
    uint16_t status;
    uint32_t class;
    uint8_t cache_line_size;
    uint8_t latency_timer;
    uint8_t header_type;
    uint8_t bist;
    uint32_t bars[6];
    uint32_t cardbus;
    uint16_t subsystem_vendor;
    uint16_t subsystem_device;
} __attribute__((packed));

int
dump_pci_file(fd_t file)
{
    struct pci_config_space hdr;

    kanawha_sys_seek(file, 0, SEEK_SET);

    ssize_t total_read = 0;

    while(total_read < sizeof(struct pci_config_space))
    {
        ssize_t read =
            kanawha_sys_read(file,
                             ((void *)&hdr) + total_read,
                             sizeof(struct pci_config_space) - total_read);
        if(read <= 0)
        {
            return -EINVAL;
        }
        total_read += read;
    }

    struct pciid *id;
    id = lookup_pciid(
            hdr.vendor_id,
            hdr.device_id,
            hdr.class,
            hdr.subsystem_vendor,
            hdr.subsystem_device);
    if(id == NULL) {
        printf("failed to lookup pciid!\n");
    }

    printf("[%x:%x]\n", hdr.vendor_id, hdr.device_id);
    if(id && id->vendor_valid) {
        printf("\tvendor=\"%s\"\n", id->vendor);
    }
    if(id && id->device_valid) {
        printf("\tdevice=\"%s\"\n", id->device);
    }
    if(id && id->subsystem_valid) {
        printf("\tsubsystem=\"%s\"\n", id->subsystem);
    }
    if(id && id->class_valid) {
        printf("\tclass=\"%s\"\n", id->class);
    }
    if(id && id->subclass_valid) {
        printf("\tsubclass=\"%s\"\n", id->class);
    }
    // printf("\tcommand=0x%x\n", hdr.command);
    // printf("\tstatus=0x%x\n", hdr.status);
    // printf("\tclass=0x%x\n", hdr.class);
    // printf("\tcache_line_size=0x%x\n", hdr.cache_line_size);
    // printf("\tlatency_timer=0x%x\n", hdr.latency_timer);
    // printf("\theader_type=0x%x\n", hdr.header_type);
    // printf("\tbist=0x%x\n", hdr.bist);

    free_pciid(id);

    return 0;
}
