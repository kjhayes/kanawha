
#include <drivers/usb/xhci/ctx.h>
#include <drivers/usb/xhci/xhci.h>
#include <drivers/usb/xhci/reg.h>

#include <kanawha/kmalloc.h>
#include <kanawha/dma.h>
#include <kanawha/errno.h>

struct usb_xhci_input_ctx {
    struct usb_xhci *xhci;
    size_t size;
    dma_addr_t dma_buffer;
};

struct usb_xhci_input_ctx *
usb_xhci_create_input_ctx(
        struct usb_xhci *xhci
        )
{
    int res;

    struct usb_xhci_input_ctx *ctx;
    ctx = kmalloc(sizeof(*ctx));
    if(ctx == NULL) {
        return NULL;
    }
    memset(ctx, 0, sizeof(*ctx));

    ctx->xhci = xhci;
    ctx->size = (usb_xhci_read(ctx->xhci, CSZ) ? 64 : 32) * 33;

    res = dma_alloc(
            ctx->size,
            4, // 16-byte aligned
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
usb_xhci_destroy_input_ctx(
        struct usb_xhci_input_ctx *ctx
        )
{
    int res;

    res = dma_free(ctx->dma_buffer, ctx->size);
    if(res) {
        return res;
    }

    kfree(ctx);

    return 0;
}

void *
usb_xhci_input_ctx_add_ctx(
        struct usb_xhci_input_ctx *ctx,
        size_t ctx_index)
{
    if(ctx_index > 31) {
        return NULL;
    }

    uint32_t *virt = dma_virt_addr(ctx->dma_buffer);

    virt[1] |= (1ULL<<ctx_index);
    printk("add_flags=0x%x\n", virt[1]);

    size_t ctx_size = usb_xhci_read(ctx->xhci, CSZ) ? 64 : 32;
    return dma_virt_addr(ctx->dma_buffer) + ((1+ctx_index) * ctx_size);
}

int
usb_xhci_input_ctx_drop_ctx(
        struct usb_xhci_input_ctx *ctx,
        size_t ctx_index)
{
    if(ctx_index > 31 || ctx_index <= 1) {
        return -EINVAL;
    }

    uint32_t *virt = dma_virt_addr(ctx->dma_buffer);

    virt[0] |= (1ULL<<ctx_index);
    printk("drop_flags=0x%x\n", virt[0]);

    return 0;
}

size_t
usb_xhci_input_ctx_entry_size(
        struct usb_xhci_input_ctx *ctx)
{
    return usb_xhci_read(ctx->xhci, CSZ) ? 64 : 32;
}

void __phys *
usb_xhci_input_ctx_phys_addr(
        struct usb_xhci_input_ctx *ctx)
{
    return dma_phys_addr(ctx->dma_buffer);
}

