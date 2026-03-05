
#include <drivers/fb/virtio_gpu.h>
#include <drivers/virtio/device.h>
#include <drivers/virtio/queue.h>
#include <drivers/virtio/request.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>

struct virtio_gpu_resource *
virtio_gpu_create_resource_2d(struct virtio_gpu *gpu,
                              size_t width,
                              size_t height,
                              enum virtio_gpu_formats format)
{
    int res;

    struct virtio_gpu_resource *resource;
    resource = kzmalloc(sizeof(struct virtio_gpu_resource), KM_KERNEL);
    if(resource == NULL)
    {
        wprintk("virtio_gpu_create_resource_2d: could not allocate resource "
                "struct!\n");
        return NULL;
    }

    resource->width = width;
    resource->height = height;
    resource->gpu = gpu;

    spin_lock(&gpu->resource_lock);

    int res_id = 0;
    for(size_t i = 1; i < 1ULL << 31; i++)
    {
        struct ptree_node *node = ptree_get(&gpu->resource_tree, i);
        if(node == NULL)
        {
            res_id = i;
            break;
        }
    }
    if(res_id == 0)
    {
        wprintk("virtio_gpu_create_resource_2d: could not allocate a resource "
                "id!\n");
        spin_unlock(&gpu->resource_lock);
        kfree(resource);
        return NULL;
    }

    dprintk("virtio_gpu_create_resource_2d -> id=0x%lx\n", (ul_t)res_id);

    res = ptree_insert(&gpu->resource_tree, &resource->tree_node, res_id);
    if(res)
    {
        wprintk("virtio_gpu_create_resource_2d: could not insert "
                "resource into "
                "GPU resource tree!\n");
        spin_unlock(&gpu->resource_lock);
        kfree(resource);
        return NULL;
    }

    resource->id = res_id;

    struct virtio_gpu_resource_create_2d req_data;
    memset(&req_data, 0, sizeof(struct virtio_gpu_resource_create_2d));
    req_data.hdr.type = VIRTIO_GPU_CMD_RESOURCE_CREATE_2D;
    req_data.width = htole32(width);
    req_data.height = htole32(height);
    req_data.format = htole32(format);
    req_data.resource_id = htole32(res_id);

    struct virtio_gpu_ctrl_hdr resp_data;

    dprintk("starting transaction...\n");
    res = virtio_transact_1_1(gpu->control_queue,
                              &req_data,
                              sizeof(req_data),
                              &resp_data,
                              sizeof(resp_data));
    dprintk("after transaction...\n");
    if(res)
    {
        wprintk("virtio_gpu_create_resource_2d: virtio transaction failed!\n");
        ptree_remove(&gpu->resource_tree, res_id);
        spin_unlock(&gpu->resource_lock);
        kfree(resource);
        return NULL;
    }

    uint32_t resp_code = letoh32(resp_data.type);
    if(resp_code != VIRTIO_GPU_RESP_OK_NODATA)
    {
        wprintk("virtio_gpu_create_resource_2d: device rejected transaction "
                "(resp_code=0x%lx)!\n",
                (ul_t)resp_code);
        ptree_remove(&gpu->resource_tree, res_id);
        spin_unlock(&gpu->resource_lock);
        kfree(resource);
        return NULL;
    }

    spin_unlock(&gpu->resource_lock);

    return resource;
}

int
virtio_gpu_destroy_resource_2d(struct virtio_gpu_resource *resource)
{
    int res;

    struct virtio_gpu *gpu = resource->gpu;

    spin_lock(&gpu->resource_lock);

    struct ptree_node *pnode;
    pnode = ptree_remove(&gpu->resource_tree, resource->id);
    if(pnode == NULL)
    {
        spin_unlock(&gpu->resource_lock);
        return -ENXIO;
    }

    DEBUG_ASSERT(pnode == &resource->tree_node);

    spin_unlock(&gpu->resource_lock);

    DEBUG_ASSERT(resource->type == VIRTIO_GPU_RESOURCE_TYPE_2D);

    int resource_id = resource->id;
    kfree(resource);

    struct virtio_gpu_resource_unref req_data;
    memset(&req_data, 0, sizeof(struct virtio_gpu_resource_unref));
    req_data.hdr.type = VIRTIO_GPU_CMD_RESOURCE_UNREF;
    req_data.resource_id = htole32(resource_id);

    struct virtio_gpu_ctrl_hdr resp_data;

    res = virtio_transact_1_1(gpu->control_queue,
                              &req_data,
                              sizeof(req_data),
                              &resp_data,
                              sizeof(resp_data));
    if(res)
    {
        return res;
    }

    if(letoh32(resp_data.type) != VIRTIO_GPU_RESP_OK_NODATA)
    {
        return res;
    }

    return 0;
}

int
virtio_gpu_resource_attach_backing(struct virtio_gpu_resource *resource,
                                   void __phys *backing_data,
                                   size_t backing_size)
{
    int res;

    struct __packed
    {
        struct virtio_gpu_resource_attach_backing req;
        struct virtio_gpu_mem_entry mem_entry;
    } req_data;

    req_data.req.hdr.type = htole32(VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING);
    req_data.req.resource_id = htole32(resource->id);
    req_data.req.nr_entries = htole32(1);

    req_data.mem_entry.addr = (uintptr_t)backing_data;
    req_data.mem_entry.length = backing_size;

    struct virtio_gpu_ctrl_hdr resp_data;

    res = virtio_transact_1_1(resource->gpu->control_queue,
                              &req_data,
                              sizeof(req_data),
                              &resp_data,
                              sizeof(resp_data));
    if(res)
    {
        return res;
    }

    if(resp_data.type != VIRTIO_GPU_RESP_OK_NODATA)
    {
        return -EINVAL;
    }

    return 0;
}

int
virtio_gpu_resource_deattach_backing(struct virtio_gpu_resource *resource)
{
    int res;

    struct virtio_gpu_resource_detach_backing req_data;
    req_data.hdr.type = VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING;
    req_data.resource_id = resource->id;

    struct virtio_gpu_ctrl_hdr resp_data;

    res = virtio_transact_1_1(resource->gpu->control_queue,
                              &req_data,
                              sizeof(req_data),
                              &resp_data,
                              sizeof(resp_data));
    if(res)
    {
        return res;
    }

    if(resp_data.type != VIRTIO_GPU_RESP_OK_NODATA)
    {
        return -EINVAL;
    }

    return 0;
}

int
virtio_gpu_resource_transfer_to_host(struct virtio_gpu_resource *resource)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(resource));
    DEBUG_ASSERT(KERNEL_ADDR(resource->gpu));
    DEBUG_ASSERT(KERNEL_ADDR(resource->gpu->control_queue));

    struct virtio_gpu_transfer_to_host_2d req_data;
    memset(&req_data, 0, sizeof(req_data));
    req_data.hdr.type = VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D;
    req_data.resource_id = htole32(resource->id);
    req_data.r.x = htole32(0);
    req_data.r.y = htole32(0);
    req_data.r.width = htole32(resource->width);
    req_data.r.height = htole32(resource->height);
    req_data.offset = htole32(0);

    struct virtio_gpu_ctrl_hdr resp_data;

    res = virtio_transact_1_1(resource->gpu->control_queue,
                              &req_data,
                              sizeof(req_data),
                              &resp_data,
                              sizeof(resp_data));
    if(res)
    {
        return res;
    }

    if(letoh32(resp_data.type) != VIRTIO_GPU_RESP_OK_NODATA)
    {
        return -EINVAL;
    }

    return 0;
}

int
virtio_gpu_resource_flush(struct virtio_gpu_resource *resource)
{
    int res;

    struct virtio_gpu_resource_flush req_data;
    memset(&req_data, 0, sizeof(req_data));
    req_data.hdr.type = VIRTIO_GPU_CMD_RESOURCE_FLUSH;
    req_data.resource_id = htole32(resource->id);
    req_data.r.x = htole32(0);
    req_data.r.y = htole32(0);
    req_data.r.width = htole32(resource->width);
    req_data.r.height = htole32(resource->height);

    struct virtio_gpu_ctrl_hdr resp_data;

    DEBUG_ASSERT(KERNEL_ADDR(resource));
    DEBUG_ASSERT(KERNEL_ADDR(resource->gpu));
    DEBUG_ASSERT(KERNEL_ADDR(resource->gpu->control_queue));

    res = virtio_transact_1_1(resource->gpu->control_queue,
                              &req_data,
                              sizeof(req_data),
                              &resp_data,
                              sizeof(resp_data));
    if(res)
    {
        return res;
    }

    if(letoh32(resp_data.type) != VIRTIO_GPU_RESP_OK_NODATA)
    {
        return -EINVAL;
    }

    return 0;
}
