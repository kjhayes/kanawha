
#include <drivers/virtio/monitor.h>
#include <drivers/virtio/queue.h>
#include <drivers/virtio/request.h>
#include <kanawha/kmalloc.h>

typedef enum {
    VIRTIO_MONITOR_STATUS_INIT,
    VIRTIO_MONITOR_STATUS_STARTING,
    VIRTIO_MONITOR_STATUS_STARTED,
    VIRTIO_MONITOR_STATUS_STOPPING,
    VIRTIO_MONITOR_STATUS_STOPPED,
} virtio_monitor_status_t;

struct virtio_monitor_request {
    struct virtio_monitor *monitor;
    struct virtio_request *request;
    dma_addr_t buffer;
};

struct virtio_monitor {
    struct virtio_queue *queue;
    int(*callback)(
            void *buffer,
            size_t buflen,
            void *state);
    void *state;

    virtio_monitor_status_t status;

    size_t buflen;

    size_t num_reqs;
    struct virtio_monitor_request *requests;
};

static inline int 
virtio_monitor_set_status(
        struct virtio_monitor *monitor,
        virtio_monitor_status_t status)
{
    monitor->status = status;
    return 0;
}
static inline virtio_monitor_status_t
virtio_monitor_status(struct virtio_monitor *monitor)
{
    return monitor->status;
}

void virtio_monitor_request_callback(
        struct virtio_request *virtio_request,
        void *priv_state)
{
    int res;

    struct virtio_monitor_request *req = priv_state;
    struct virtio_monitor *monitor = req->monitor;

    DEBUG_ASSERT(virtio_request == req->request);

    void *buffer = dma_virt_addr(req->buffer);
    size_t len = req->request->len_written;

    if(req->monitor->callback) {
        (*req->monitor->callback)(
                buffer,
                len,
                req->monitor->state
                );
    }

    switch(virtio_monitor_status(monitor)) {
        case VIRTIO_MONITOR_STATUS_STARTING:
        case VIRTIO_MONITOR_STATUS_STARTED:
            res = virtio_request_launch(virtio_request);
            if(res) {
                wprintk("virtio_monitor_request_callback: failed to relaunch request! (err=%s)\n",
                        errnostr(res));
            }
            break;
        default:
            break;
    }

    return;
}

static inline int
virtio_monitor_request_init(
        struct virtio_monitor *mon,
        struct virtio_monitor_request *req)
{
    int res;
    req->monitor = mon;
    req->request = virtio_request_create(mon->queue);
    if(req->request == NULL) {
        eprintk("virtio_monitor_request: failed to create virtio request!\n");
        return -ENOMEM;
    }
    res = dma_alloc(
            mon->buflen,
            4,
            DMA_PHYS_64,
            &req->buffer);
    if(res) {
        eprintk("virtio_monitor_request: failed to allocate dma buffer!\n");
        virtio_request_destroy(req->request);
        return res;
    }
    res = virtio_request_append_output(
            req->request,
            dma_phys_addr(req->buffer),
            mon->buflen);
    if(res) {
        eprintk("virtio_monitor_request: failed to append dma buffer to request! (err=%s)\n",
                errnostr(res));
        virtio_request_destroy(req->request);
        dma_free(req->buffer, mon->buflen);
        return res;
    }
    res = virtio_request_set_completion_callback(
            req->request,
            virtio_monitor_request_callback,
            req);
    if(res) {
        eprintk("virtio_monitor_request: failed to set completion callback! (err=%s)\n",
                errnostr(res));
        virtio_request_destroy(req->request);
        dma_free(req->buffer, mon->buflen);
        return res;
    }
    return 0;
}

static inline int
virtio_monitor_request_deinit(
        struct virtio_monitor *mon,
        struct virtio_monitor_request *req)
{
    int res;
    res = virtio_request_destroy(req->request);
    if(res) {
        return res;
    }
    dma_free(req->buffer, mon->buflen);
    return 0;
}

struct virtio_monitor *
virtio_monitor_create(
        struct virtio_queue *queue,
        size_t max_reqs,
        size_t buflen,
        int(*callback)(void *buffer, size_t buflen, void *state),
        void *state)
{
    int res;

    struct virtio_monitor *monitor;
    monitor = kmalloc(sizeof(*monitor), KM_KERNEL);
    if(monitor == NULL) {
        eprintk("virtio_monitor: failed to allocate monitor struct!\n");
        return NULL;
    }
    monitor->queue = queue;
    monitor->callback = callback;
    monitor->state = state;
    monitor->buflen = buflen;
    monitor->num_reqs = max_reqs;
    monitor->requests = kzmalloc(sizeof(struct virtio_monitor_request) * monitor->num_reqs, KM_KERNEL);
    if(monitor->requests == NULL) {
        eprintk("virtio_monitor: failed to allocate requests array!\n");
        kfree(monitor);
        return NULL;
    }
    monitor->status = VIRTIO_MONITOR_STATUS_INIT;

    for(size_t i = 0; i < monitor->num_reqs; i++) {
        res = virtio_monitor_request_init(monitor, &monitor->requests[i]);
        if(res) {
            eprintk("virtio_monitor: failed to initialize monitor request! (err=%s)\n",
                    errnostr(res));
            for(size_t j = 0; j < i; j++) {
                virtio_monitor_request_deinit(monitor, &monitor->requests[j]);
            }
            virtio_queue_disable(monitor->queue);
            kfree(monitor->requests);
            kfree(monitor);
            return NULL;
        }
    }
    
    virtio_monitor_set_status(monitor, VIRTIO_MONITOR_STATUS_STOPPED);
    return monitor;
}

int
virtio_monitor_destroy(
        struct virtio_monitor *monitor)
{
    int res;

    // Wait for the monitor to fully stop
    int running = 1;
    while(running) {
        switch(virtio_monitor_status(monitor)) {
            case VIRTIO_MONITOR_STATUS_INIT:
            case VIRTIO_MONITOR_STATUS_STOPPED:
                running = 0;
                break;
            case VIRTIO_MONITOR_STATUS_STOPPING:
                break;
            default:
                return -EINVAL;
        }
    }
    
    // Destroy every request
    for(size_t i = 0; i < monitor->num_reqs; i++) {
        res = virtio_monitor_request_deinit(monitor, &monitor->requests[i]);
        if(res) {
            panic("virtio_monitor_destroy: failed to destroy virtio_request! (err=%s)\n",
                    errnostr(res));
        }
    }
    virtio_queue_disable(monitor->queue);
    kfree(monitor->requests);
    kfree(monitor);
    return 0;
}

int
virtio_monitor_start(
        struct virtio_monitor *monitor)
{
    int res;
    res = virtio_monitor_set_status(monitor, VIRTIO_MONITOR_STATUS_STARTING);
    if(res) {
        return res;
    }

    res = virtio_queue_enable(monitor->queue);
    if(res) {
        eprintk("virtio_monitor: failed to enable virtio queue! (err=%s)\n",
                errnostr(res));
        kfree(monitor->requests);
        kfree(monitor);
        return res;
    }

    for(size_t i = 0; i < monitor->num_reqs; i++) {
        struct virtio_monitor_request *req = &monitor->requests[i];
        res = virtio_request_launch(req->request);
        if(res) {
            wprintk("virtio_monitor_start: failed to launch virtio request! (err=%s)\n",
                    errnostr(res));
        }
    }

    res = virtio_monitor_set_status(monitor, VIRTIO_MONITOR_STATUS_STARTED);
    if(res) {
        return res;
    }
    return 0;
}
int
virtio_monitor_stop(
        struct virtio_monitor *monitor)
{
    int res;
    res = virtio_monitor_set_status(monitor, VIRTIO_MONITOR_STATUS_STOPPING);
    if(res) {
        return res;
    }

    for(size_t i = 0; i < monitor->num_reqs; i++) {
        struct virtio_monitor_request *req = &monitor->requests[i];
        res = virtio_request_await(req->request);
        if(res) {
            wprintk("virtio_monitor_stop: failed to await virtio request! (err=%s)\n",
                    errnostr(res));
        }
    }

    res = virtio_queue_disable(monitor->queue);
    if(res) {
        eprintk("virtio_monitor: failed to disable virtio queue! (err=%s)\n",
                errnostr(res));
        kfree(monitor->requests);
        kfree(monitor);
        return res;
    }

    res = virtio_monitor_set_status(monitor, VIRTIO_MONITOR_STATUS_STOPPED);
    if(res) {
        return res;
    }
    return 0;
}

