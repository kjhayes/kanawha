
#include <kanawha/sys-wrappers.h>
#include <kanawha/file.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

struct acpi_table_hdr {
    uint8_t signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oem_id[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} __attribute__((packed));

int
dump_acpi_file(fd_t file)
{
    size_t file_size = kanawha_sys_seek(file, 0, SEEK_END);

    if(file_size < sizeof(struct acpi_table_hdr)) {
        fprintf(stderr, "ACPI table sysfs file is too small to fit table header!\n");
        return -EINVAL;
    }

    void *buffer = malloc(file_size);
    if(buffer == NULL) {
        fprintf(stderr, "Ran out of memory!\n");
        return -ENOMEM;
    }

    kanawha_sys_seek(file, 0, SEEK_SET);

    ssize_t total_read = 0;

    while(total_read < file_size) {
        ssize_t read =
            kanawha_sys_read(
                    file,
                    buffer+total_read,
                    file_size-total_read);
        if(read <= 0) {
            free(buffer);
            return -EINVAL;
        }
        total_read += read;
    }

    struct acpi_table_hdr *hdr = (struct acpi_table_hdr*)buffer;

    printf("[%c%c%c%c] {\n",
            hdr->signature[0],
            hdr->signature[1],
            hdr->signature[2],
            hdr->signature[3]);
    printf("\tLength=0x%x\n", hdr->length);
    printf("\tRevision=0x%x\n", hdr->revision);
    printf("\tChecksum=0x%x\n", hdr->checksum);
    printf("\tOEM ID=\"%c%c%c%c%c%c\"\n",
            hdr->oem_id[0],
            hdr->oem_id[1],
            hdr->oem_id[2],
            hdr->oem_id[3],
            hdr->oem_id[4],
            hdr->oem_id[5]
            );
    printf("\tOEM Table ID=\"%c%c%c%c%c%c%c%c\"\n",
            hdr->oem_table_id[0],
            hdr->oem_table_id[1],
            hdr->oem_table_id[2],
            hdr->oem_table_id[3],
            hdr->oem_table_id[4],
            hdr->oem_table_id[5],
            hdr->oem_table_id[6],
            hdr->oem_table_id[7]
            );
    printf("\tOEM Revision=0x%x\n", hdr->oem_revision);
    printf("\tCreator ID=0x%x\n", hdr->creator_id);
    printf("\tCreator Revision=0x%x\n", hdr->creator_revision);
    printf("}\n");

    free(buffer);
    return 0;
}

