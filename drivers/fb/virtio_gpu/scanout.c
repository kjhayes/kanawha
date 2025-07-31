
#include <drivers/fb/virtio_gpu.h>
#include <drivers/virtio/request.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/dma.h>

int
virtio_gpu_update_scanout_info(
        struct virtio_gpu *gpu)
{
    int res;

    struct virtio_gpu_ctrl_hdr req_data;
    memset(&req_data, 0, sizeof(struct virtio_gpu_ctrl_hdr));
    req_data.type = VIRTIO_GPU_CMD_GET_DISPLAY_INFO;

    struct virtio_gpu_resp_display_info resp_data;

    res = virtio_transact_1_1(
            gpu->control_queue,
            &req_data,
            sizeof(req_data),
            &resp_data,
            sizeof(resp_data));
    if(res) {
        return res;
    }

    // TODO
    gpu->num_scanouts = VIRTIO_GPU_MAX_SCANOUTS;
    gpu->num_enabled_scanouts = 0;

    if(gpu->scanouts != NULL) {
        kfree(gpu->scanouts);
    }

    gpu->scanouts = kzmalloc(sizeof(struct virtio_gpu_scanout) * gpu->num_scanouts, KM_KERNEL);
    if(gpu->scanouts == NULL) {
        return -ENOMEM;
    }

    for(size_t i = 0; i < gpu->num_scanouts; i++) {
        struct virtio_gpu_scanout *scanout = &gpu->scanouts[i];
        struct virtio_gpu_resp_display_info *resp = &resp_data;
        struct virtio_gpu_display_one *pmode = &resp->pmodes[i];

        scanout->enabled = pmode->enabled;
        if(scanout->enabled) {
            gpu->num_enabled_scanouts++;
        }
        scanout->pref_width = pmode->r.width;
        scanout->pref_height = pmode->r.height;
        scanout->pref_pos_x = pmode->r.x;
        scanout->pref_pos_y = pmode->r.x;
    }

    return 0;
}

int
virtio_gpu_set_scanout(
        struct virtio_gpu *gpu,
        int scanout_index,
        size_t width,
        size_t height,
        struct virtio_gpu_resource *resource)
{
    int res;

    dprintk("virtio_gpu_set_scanout\n");

    struct virtio_gpu_set_scanout req_data;
    req_data.hdr.type = VIRTIO_GPU_CMD_SET_SCANOUT;
    req_data.scanout_id = htole32(scanout_index);
    req_data.resource_id = htole32(resource->id);
    req_data.r.width = htole32(width);
    req_data.r.height = htole32(height);
    req_data.r.x = htole32(0);
    req_data.r.y = htole32(0);

    struct virtio_gpu_ctrl_hdr resp_data;

    res = virtio_transact_1_1(
            gpu->control_queue,
            &req_data,
            sizeof(req_data),
            &resp_data,
            sizeof(resp_data));
    dprintk("virtio_gpu_set_scanout after transact\n");
    if(res) {
        return res;
    }

    if(letoh32(resp_data.type) != VIRTIO_GPU_RESP_OK_NODATA) {
        return -EINVAL;
    }

    return 0;
}

