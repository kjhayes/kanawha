
#include <drivers/usb/xhci/ctx.h>
#include <drivers/usb/xhci/reg.h>
#include <drivers/usb/xhci/xhci.h>

#include <kanawha/dma.h>
#include <kanawha/errno.h>
#include <kanawha/kmalloc.h>

/*
 * Input Context
 */

struct usb_xhci_input_ctx
{
    struct usb_xhci *xhci;
    size_t entry_size;
    size_t size;
    dma_addr_t dma_buffer;
};

struct usb_xhci_input_ctx *
usb_xhci_create_input_ctx(struct usb_xhci *xhci)
{
    int res;

    struct usb_xhci_input_ctx *ctx;
    ctx = kzmalloc(sizeof(*ctx), KM_KERNEL);
    if(ctx == NULL)
    {
        return NULL;
    }

    ctx->xhci = xhci;
    ctx->entry_size = (usb_xhci_read(ctx->xhci, CSZ) ? 64 : 32);
    ctx->size = ctx->entry_size * 33;

    res = dma_alloc(ctx->size,
                    VMEM_MIN_PAGE_ORDER, // 16-byte aligned but must be within a single physical page
                    usb_xhci_read(xhci, AC64) ? DMA_PHYS_64 : DMA_PHYS_32,
                    &ctx->dma_buffer);
    if(res)
    {
        kfree(ctx);
        return NULL;
    }

    void *virt = dma_virt_addr(ctx->dma_buffer);
    memset(virt, 0, ctx->size);

    return ctx;
}

int
usb_xhci_destroy_input_ctx(struct usb_xhci_input_ctx *ctx)
{
    int res;

    res = dma_free(ctx->dma_buffer, ctx->size);
    if(res)
    {
        return res;
    }

    kfree(ctx);

    return 0;
}
int
usb_xhci_input_ctx_reset_add_drop(
        struct usb_xhci_input_ctx *ctx)
{
    uint32_t *virt;
    virt = dma_virt_addr(ctx->dma_buffer);
    virt[0] = 0;
    virt[1] = 0;
    return 0;
}

int
usb_xhci_input_ctx_mark_add_ctx(
        struct usb_xhci_input_ctx *ctx,
        int dci)
{
    if(dci > 31)
    {
        return -EINVAL;
    }

    uint32_t *virt = dma_virt_addr(ctx->dma_buffer);

    virt[1] |= (1ULL << dci);

    return 0;
}

int
usb_xhci_input_ctx_mark_drop_ctx(
        struct usb_xhci_input_ctx *ctx,
        int dci)
{
    if(dci > 31 || dci <= 1)
    {
        return -EINVAL;
    }

    uint32_t *virt = dma_virt_addr(ctx->dma_buffer);

    virt[0] |= (1ULL << dci);

    return 0;
}

size_t
usb_xhci_input_ctx_entry_size(struct usb_xhci_input_ctx *ctx)
{
    return ctx->entry_size;
}

void __phys *
usb_xhci_input_ctx_phys_addr(struct usb_xhci_input_ctx *ctx)
{
    return dma_phys_addr(ctx->dma_buffer);
}

struct usb_xhci_slot_ctx *
usb_xhci_input_ctx_slot_ctx(
        struct usb_xhci_input_ctx *ctx)
{
    void *data = dma_virt_addr(ctx->dma_buffer);
    return data + ctx->entry_size;
}

struct usb_xhci_endpoint_ctx *
usb_xhci_input_ctx_endpoint_ctx(
        struct usb_xhci_input_ctx *ctx,
        int dci)
{
    void *data = dma_virt_addr(ctx->dma_buffer);
    DEBUG_ASSERT(dci > 0);
    return data + (ctx->entry_size * (1+dci));
}

/*
 * Device Context
 */

struct usb_xhci_device_ctx
{
    struct usb_xhci *xhci;
    size_t entry_size;
    size_t size;
    dma_addr_t dma_buffer;
};

struct usb_xhci_device_ctx *
usb_xhci_create_device_ctx(struct usb_xhci *xhci)
{
    int res;

    struct usb_xhci_device_ctx *ctx;
    ctx = kzmalloc(sizeof(*ctx), KM_KERNEL);
    if(ctx == NULL) {
        return NULL;
    }
    ctx->xhci = xhci;

    ctx->entry_size = usb_xhci_read(xhci, CSZ) ? 64 : 32;
    ctx->size = ctx->entry_size * 32;
    res = dma_alloc(
            ctx->size,
            VMEM_MIN_PAGE_ORDER, // 16-byte aligned (but might need to be within one page?)
            usb_xhci_read(xhci, AC64) ? DMA_PHYS_64 : DMA_PHYS_32,
            &ctx->dma_buffer);
    if(res) {
        kfree(ctx);
        return NULL;
    }

    void *virt = dma_virt_addr(ctx->dma_buffer);
    memset(virt, 0, ctx->size);

    return ctx;
}

int
usb_xhci_destroy_device_ctx(struct usb_xhci_device_ctx *ctx)
{
    dma_free(ctx->dma_buffer, ctx->size);
    kfree(ctx);
    return 0;
}

void __phys *
usb_xhci_device_ctx_phys_addr(
        struct usb_xhci_device_ctx *ctx)
{
    return dma_phys_addr(ctx->dma_buffer);
}

