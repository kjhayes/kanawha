
#include <drivers/virtio/queue.h>
#include <drivers/virtio/request.h>
#include <kanawha/kmalloc.h>
#include <kanawha/bitmap.h>
#include <kanawha/string.h>
#include <kanawha/spinlock.h>
#include <kanawha/irq.h>
#include <kanawha/stddef.h>
#include <kanawha/mbarrier.h>

int
virtio_queue_init_struct(
        struct virtio_queue *queue,
        struct virtio_queue_ops *ops,
        struct virtio_device *device,
        uint16_t index,
        uint16_t queue_size)
{
    int res;

    queue->ops = ops;
    queue->device = device;
    queue->index = index;
    queue->queue_size = queue_size;

    queue->last_used_idx = 0;

    spinlock_init(&queue->req_lock);
    spinlock_init(&queue->avail_lock);
    spinlock_init(&queue->used_lock);
    ilist_init(&queue->unlaunched_reqs);
    ilist_init(&queue->launched_reqs);
    ilist_init(&queue->complete_reqs);

    queue->desc_bitmap = kmalloc(BITMAP_SIZE(queue_size));
    if(queue->desc_bitmap == NULL) {
        kfree(queue);
        return -ENOMEM;
    }
    // Every Descriptor Starts as Zero (Free)
    memset(queue->desc_bitmap, 0, BITMAP_SIZE(queue_size));

    queue->avail_bitmap = kmalloc(BITMAP_SIZE(queue_size));
    if(queue->avail_bitmap == NULL) {
        kfree(queue->desc_bitmap);
        kfree(queue);
        return -ENOMEM;
    }
    memset(queue->avail_bitmap, 0, BITMAP_SIZE(queue_size));

    size_t desc_table_size = 16 * queue_size;
    size_t avail_ring_size = 6 + (2 * queue_size);
    size_t used_ring_size = 6 + (8 * queue_size);

    size_t desc_table_offset = 0;
    size_t avail_ring_offset = desc_table_size;
    size_t used_ring_offset = ((desc_table_size + avail_ring_size) + (PAGE_SIZE_4KB-1)) & ~(PAGE_SIZE_4KB-1);

    queue->dma_size = used_ring_offset + used_ring_size;

    res = dma_alloc(
            queue->dma_size,
            12,
            DMA_PHYS_64,
            &queue->dma_region);
    if(res) {
        eprintk("virtio_queue: Failed to allocate dma region! (err=%s)\n",
                errnostr(res));
        kfree(queue->desc_bitmap);
        kfree(queue->avail_bitmap);
        return res;
    }

    queue->desc_table = dma_virt_addr(queue->dma_region) + desc_table_offset;
    memset(queue->desc_table, 0, desc_table_size);
    queue->avail_ring = dma_virt_addr(queue->dma_region) + avail_ring_offset;
    memset(queue->avail_ring, 0, avail_ring_size);
    queue->used_ring = dma_virt_addr(queue->dma_region) + used_ring_offset;
    memset(queue->used_ring, 0, used_ring_size);

    res = virtio_queue_set_desc_table(
            queue,
            dma_phys_addr(queue->dma_region) + desc_table_offset);
    if(res) {
        kfree(queue->desc_bitmap);
        kfree(queue->avail_bitmap);
        dma_free(queue->dma_region, queue->dma_size);
        eprintk("virtio_queue: Failed to set descriptor table! (err=%s)\n",
                errnostr(res));
        return res;
    }
    res = virtio_queue_set_avail_ring(
            queue,
            dma_phys_addr(queue->dma_region) + avail_ring_offset);
    if(res) {
        kfree(queue->desc_bitmap);
        kfree(queue->avail_bitmap);
        dma_free(queue->dma_region, queue->dma_size);
        eprintk("virtio_queue: Failed to set avail ring! (err=%s)\n",
                errnostr(res));
        return res;
    }
    res = virtio_queue_set_used_ring(
            queue,
            dma_phys_addr(queue->dma_region) + used_ring_offset);
    if(res) {
        kfree(queue->desc_bitmap);
        kfree(queue->avail_bitmap);
        dma_free(queue->dma_region, queue->dma_size);
        eprintk("virtio_queue: Failed to set used ring! (err=%s)\n",
                errnostr(res));
        return res;
    }

    return 0;
}

int
virtio_queue_deinit_struct(
        struct virtio_queue *queue)
{
    kfree(queue->desc_bitmap);
    kfree(queue->avail_bitmap);
    dma_free(queue->dma_region, queue->dma_size);
    return 0;
}

int
virtio_queue_free_desc_chain(
        struct virtio_queue *queue,
        uint16_t root_desc)
{
    int res;

    struct virtio_queue_desc *desc_table =
        (struct virtio_queue_desc*)queue->desc_table;

    uint16_t index = root_desc;
    int has_next;

    do {

        has_next = 0;
        struct virtio_queue_desc *desc = &(desc_table[index]);
        if(desc->flags & VIRTQ_DESC_F_NEXT) {
            has_next = 1;
        }

        uint16_t next = desc->next;

        bitmap_clear(queue->desc_bitmap, index);

        index = next;

    } while(has_next);

    return 0;
}

int
virtio_queue_alloc_desc(
        struct virtio_queue *queue,
        uint16_t *index_out)
{
    spin_lock(&queue->desc_lock);

    size_t bit = bitmap_find_clear_range(
            queue->desc_bitmap,
            queue->queue_size,
            1);
    if(bit >= queue->queue_size) {
        spin_unlock(&queue->desc_lock);
        return -ENOMEM;
    }

    bitmap_set(queue->desc_bitmap, bit);

    spin_unlock(&queue->desc_lock);

    *index_out = bit;

    struct virtio_queue_desc *desc_table =
        (struct virtio_queue_desc*)queue->desc_table;

    struct virtio_queue_desc *desc = &(desc_table[bit]);

    desc->addr = 0;
    desc->len = 0;
    desc->next = 0;
    desc->flags = 0;

    return 0;
}

int
virtio_queue_alloc_chained_desc(
        struct virtio_queue *queue,
        uint16_t prev_index,
        uint16_t *index_out)
{
    int res;

    res = virtio_queue_alloc_desc(
            queue,
            index_out);
    if(res) {
        return res;
    }

    uint16_t desc_index = *index_out;

    struct virtio_queue_desc *desc_table =
        (struct virtio_queue_desc*)queue->desc_table;
   
    struct virtio_queue_desc *prev_desc = &(desc_table[prev_index]);
    struct virtio_queue_desc *desc = &(desc_table[desc_index]);

    prev_desc->next = desc_index;
    prev_desc->flags |= VIRTQ_DESC_F_NEXT;

    return 0;
}

int
virtio_queue_point_desc(
        struct virtio_queue *queue,
        uint16_t desc_index,
        void __phys *buffer,
        uint32_t size,
        int output)
{
    struct virtio_queue_desc *desc_table =
        (struct virtio_queue_desc*)queue->desc_table;
    struct virtio_queue_desc *desc = &(desc_table[desc_index]);

    dprintk("virtio_queue_point_desc %p, size=0x%lx\n",
            buffer, size);

    desc->addr = (uintptr_t)buffer;
    desc->len = size;

    desc->flags = 0; // Default to no flags
    desc->next = 0; // NULL

    if(output) {
        desc->flags |= VIRTQ_DESC_F_WRITE;
    } else {
        desc->flags &= ~VIRTQ_DESC_F_WRITE;
    }

    return 0;
}

static inline int
virtio_queue_try_push_avail_ring(
        struct virtio_queue *queue,
        struct virtio_request *req)
{
    int res;

    struct virtio_queue_avail *avail_ring =
        (struct virtio_queue_avail*)queue->avail_ring;

    spin_lock(&queue->avail_lock);

    size_t idx = avail_ring->idx;
    req->avail_slot = avail_ring->idx % queue->queue_size;

    if(bitmap_check(queue->avail_bitmap, req->avail_slot)) {
        spin_unlock(&queue->avail_lock);
        return -EBUSY;
    }

    bitmap_set(queue->avail_bitmap, idx);

    avail_ring->ring[req->avail_slot] = req->root_descriptor;
    mbarrier();
    avail_ring->idx = idx + 1;
    mbarrier();

    dprintk("avail_ring.idx 0x%lx -> 0x%lx, slot=0x%lx\n",
            idx, idx+1, req->avail_slot);

    spin_unlock(&queue->avail_lock);
 
    return 0;
}

int
virtio_queue_launch_request(
        struct virtio_queue *queue,
        struct virtio_request *req)
{
    int res;
    int irq_flags = spin_lock_irq_save(&queue->req_lock);

    if(req->state != VIRTIO_REQUEST_UNLAUNCHED) {
        spin_unlock_irq_restore(&queue->req_lock, irq_flags);
        return -EINVAL;
    }

    ilist_remove(&queue->unlaunched_reqs, &req->queue_node);
    req->state = VIRTIO_REQUEST_LAUNCHED;
    ilist_push_tail(&queue->launched_reqs, &req->queue_node);

    // Push descriptor into available queue
    res = virtio_queue_try_push_avail_ring(queue, req);
    if(res) {
        ilist_remove(&queue->launched_reqs, &req->queue_node);
        req->state = VIRTIO_REQUEST_UNLAUNCHED;
        ilist_push_tail(&queue->unlaunched_reqs, &req->queue_node);
        spin_unlock_irq_restore(&queue->req_lock, irq_flags);
        return res;
    }
    
    spin_unlock_irq_restore(&queue->req_lock, irq_flags);

    virtio_queue_notify(queue);

    return 0;
}

int
virtio_queue_try_finish_request(
        struct virtio_queue *queue,
        struct virtio_request *req)
{
    int res;
    int irq_flags = spin_lock_irq_save(&queue->req_lock);

    if(req->state != VIRTIO_REQUEST_COMPLETED) {
        spin_unlock_irq_restore(&queue->req_lock, irq_flags);
        return -EINVAL;
    }

    req->state = VIRTIO_REQUEST_UNLAUNCHED;

    spin_unlock_irq_restore(&queue->req_lock, irq_flags);
    return 0;
}

static struct virtio_request *
virtio_queue_find_launched_req_by_desc(
        struct virtio_queue *queue,
        uint16_t desc_id)
{
    ilist_node_t *node;
    ilist_for_each(node, &queue->launched_reqs) {
        struct virtio_request *req =
            container_of(node, struct virtio_request, queue_node);
        if(req->root_descriptor == desc_id) {
            return req;
        }
    }
    return NULL;
}

int
virtio_queue_handle_used_notification(
        struct virtio_queue *queue)
{
    int res;

    int irq_flags = spin_lock_irq_save(&queue->used_lock);

    struct virtio_queue_used *used_ring =
        (struct virtio_queue_used*)queue->used_ring;

    size_t last_idx = queue->last_used_idx;
    size_t idx = used_ring->idx;

    size_t num_new_elem = idx - last_idx;
    dprintk("virtio_queue_handle_used_notification (num_new_elem = 0x%lx)\n",
            num_new_elem);

    for(size_t i = 0; i < num_new_elem; i++) {
        struct virtio_queue_used_elem *elem =
            &used_ring->ring[(last_idx + i) % queue->queue_size];

        le32_t id = elem->id;
        le32_t len = elem->len;
 
        struct virtio_request *req =
            virtio_queue_find_launched_req_by_desc(
                    queue,
                    id);
        if(req == NULL) {
            eprintk("virtio_queue: Device or Driver Issue, Descriptor in Used Buffer without a corresponding launched request! (id=0x%lx)\n",
                    (ul_t)id);
            continue;
        }

        spin_lock(&queue->req_lock);
        ilist_remove(&req->queue_node, &queue->launched_reqs);
        req->len_written = len;
        req->state = VIRTIO_REQUEST_COMPLETED;
        ilist_push_tail(&req->queue_node, &queue->complete_reqs);
        spin_unlock(&queue->req_lock);

        spin_lock(&queue->avail_lock);
        bitmap_clear(queue->avail_bitmap, req->avail_slot);
        spin_unlock(&queue->avail_lock);
    }

    // Update the last seen used ring index
    queue->last_used_idx = idx;

    spin_unlock_irq_restore(&queue->used_lock, irq_flags);

    return 0;
}

