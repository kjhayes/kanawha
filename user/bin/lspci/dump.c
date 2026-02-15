
#include <kanawha/sys-wrappers.h>
#include <kanawha/file.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

struct pci_config_space {
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t command;
    uint16_t status;
    uint32_t class;
    uint8_t cache_line_size;
    uint8_t latency_timer;
    uint8_t header_type;
    uint8_t bist;
} __attribute__((packed));

int
dump_pci_file(fd_t file)
{
    struct pci_config_space hdr;

    kanawha_sys_seek(file, 0, SEEK_SET);

    ssize_t total_read = 0;

    while(total_read < sizeof(struct pci_config_space)) {
        ssize_t read =
            kanawha_sys_read(
                    file,
                    ((void*)&hdr)+total_read,
                    sizeof(struct pci_config_space)-total_read);
        if(read <= 0) {
            return -EINVAL;
        }
        total_read += read;
    }

    printf("[%x:%x] {\n",
            hdr.vendor_id,
            hdr.device_id
            );
    printf("\tcommand=0x%x\n", hdr.command);
    printf("\tstatus=0x%x\n", hdr.status);
    printf("\tclass=0x%x\n", hdr.class);
    printf("\tcache_line_size=0x%x\n", hdr.cache_line_size);
    printf("\tlatency_timer=0x%x\n", hdr.latency_timer);
    printf("\theader_type=0x%x\n", hdr.header_type);
    printf("\tbist=0x%x\n", hdr.bist);
    printf("}\n");

    return 0;
}

