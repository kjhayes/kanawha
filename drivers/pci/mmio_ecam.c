
#include <drivers/pci/cfg.h>
#include <drivers/pci/pci.h>
#include <drivers/pci/mmio_ecam.h>
#include <kanawha/init.h>

static inline void * 
mmio_ecam_compute_pointer(
        struct pci_cam *cam,
        uint16_t seg,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset)
{
    // TODO Add the segment into the computation
    size_t base = 
        ((size_t)bus) << 20
      | ((size_t)device) << 15
      | ((size_t)func) << 12;

    size_t final_offset = base + offset;

    struct mmio_pci_ecam *ecam =
        container_of(cam, struct mmio_pci_ecam, cam);

    DEBUG_ASSERT(final_offset <= ecam->size);

    return __va(ecam->base_addr + final_offset);
}

static int
mmio_ecam_pci_readb(
        struct pci_cam *cam,
        uint16_t seg,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint8_t *out
        )
{
    void *ptr = mmio_ecam_compute_pointer(cam, seg, bus, device, func, offset);
    *out = *(volatile uint8_t*)ptr;
    return 0;
}

static int
mmio_ecam_pci_readw(
        struct pci_cam *cam,
        uint16_t seg,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint16_t *out
        )
{
    void *ptr = mmio_ecam_compute_pointer(cam, seg, bus, device, func, offset);
    *out = *(volatile uint16_t*)ptr;
    return 0;
}

static int
mmio_ecam_pci_readl(
        struct pci_cam *cam,
        uint16_t seg,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint32_t *out
        )
{
    void *ptr = mmio_ecam_compute_pointer(cam, seg, bus, device, func, offset);
    *out = *(volatile uint32_t*)ptr;
    return 0;
}

static int
mmio_ecam_pci_writeb(
        struct pci_cam *cam,
        uint16_t seg,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint8_t in 
        )
{
    void *ptr = mmio_ecam_compute_pointer(cam, seg, bus, device, func, offset);
    *(volatile uint8_t*)ptr = in;
    return 0;
}

static int
mmio_ecam_pci_writew(
        struct pci_cam *cam,
        uint16_t seg,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint16_t in 
        )
{
    void *ptr = mmio_ecam_compute_pointer(cam, seg, bus, device, func, offset);
    *(volatile uint16_t*)ptr = in;
    return 0;
}

static int
mmio_ecam_pci_writel(
        struct pci_cam *cam,
        uint16_t seg,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint32_t in 
        )
{
    void *ptr = mmio_ecam_compute_pointer(cam, seg, bus, device, func, offset);
    *(volatile uint32_t*)ptr = in;
    return 0;
}

static struct pci_cam
mmio_ecam_pci_cam = {
    .readb = mmio_ecam_pci_readb,
    .readw = mmio_ecam_pci_readw,
    .readl = mmio_ecam_pci_readl,
    .writeb = mmio_ecam_pci_writeb,
    .writew = mmio_ecam_pci_writew,
    .writel = mmio_ecam_pci_writel,
};


int
register_pci_mmio_ecam(
        struct mmio_pci_ecam *cam,
        void __phys *base_addr,
        size_t size)
{
    int res;

    cam->base_addr = base_addr;
    cam->size = size;

    res = register_pci_cam(
            &cam->cam,
            PCI_CAM_FLAG_EXTENDED);
    if(res) {
        return res;
    }

    return 0;
}

