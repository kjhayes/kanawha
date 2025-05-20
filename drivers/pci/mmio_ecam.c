
#include <drivers/pci/cfg.h>
#include <drivers/pci/pci.h>
#include <drivers/pci/mmio_ecam.h>
#include <kanawha/init.h>
#include <kanawha/errno.h>

static inline int
mmio_ecam_compute_pointer(
        struct pci_cam *cam,
        uint16_t seg,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        void **out)
{
    size_t base = 
        ((size_t)bus) << 20
      | ((size_t)device) << 15
      | ((size_t)func) << 12;

    size_t final_offset = base + offset;

    struct mmio_pci_ecam *ecam =
        container_of(cam, struct mmio_pci_ecam, cam);

    if(seg != ecam->segment_id) {
        return -EINVAL;
    }

    if(final_offset > ecam->size) {
        return -EINVAL;
    }

    dprintk("mmio_ecam_offset = %p\n", final_offset);
    dprintk("mmio_pointer = %p\n", ecam->base_addr + final_offset);

    *out = __va(ecam->base_addr + final_offset);

    return 0;
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
    int res;
    void *ptr;
    res = mmio_ecam_compute_pointer(cam, seg, bus, device, func, offset, &ptr);
    if(res) {return res;}
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
    int res;
    void *ptr;
    res = mmio_ecam_compute_pointer(cam, seg, bus, device, func, offset, &ptr);
    if(res) {return res;}
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
    int res;
    void *ptr;
    res = mmio_ecam_compute_pointer(cam, seg, bus, device, func, offset, &ptr);
    if(res) {return res;}
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
    int res;
    void *ptr;
    res = mmio_ecam_compute_pointer(cam, seg, bus, device, func, offset, &ptr);
    if(res) {return res;}
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
    int res;
    void *ptr;
    res = mmio_ecam_compute_pointer(cam, seg, bus, device, func, offset, &ptr);
    if(res) {return res;}
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
    int res;
    void *ptr;
    res = mmio_ecam_compute_pointer(cam, seg, bus, device, func, offset, &ptr);
    if(res) {return res;}
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
register_mmio_pci_ecam(
        struct mmio_pci_ecam *cam,
        uint16_t segment_id,
        void __phys *base_addr,
        size_t size)
{
    int res;

    cam->base_addr = base_addr;
    cam->size = size;
    cam->segment_id = segment_id;
    cam->cam = mmio_ecam_pci_cam;

    res = register_pci_cam(
            &cam->cam,
            PCI_CAM_FLAG_EXTENDED);
    if(res) {
        return res;
    }

    return 0;
}

