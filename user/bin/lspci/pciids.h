#ifndef __LSPCI_PCIIDS_H__
#define __LSPCI_PCIIDS_H__

#include <stdint.h>

int init_pciids(const char *path);
int deinit_pciids(void);

struct pciid {
    unsigned vendor_valid : 1;
    const char *vendor;

    unsigned device_valid : 1;
    const char *device;

    unsigned subsystem_valid : 1;
    const char *subsystem;

    unsigned class_valid : 1;
    const char *class;

    unsigned subclass_valid : 1;
    const char *subclass;
};

struct pciid *
lookup_pciid(
        uint16_t vendor,
        uint16_t device,
        uint32_t cls,
        uint16_t subsystem_vendor,
        uint16_t subsystem_id);

int
free_pciid(
        struct pciid *id);

#endif
