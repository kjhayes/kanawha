
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>
#include <kanawha/irq.h>
#include <kanawha/lock.h>
#include <kanawha/dev/snd.h>
#include <drivers/virtio/driver.h>
#include <drivers/virtio/virtio.h>
#include <drivers/virtio/queue.h>
#include <drivers/virtio/request.h>
#include <kanawha/endian.h>

#define VIRTIO_SND_STREAM_BUFLEN (0x1000)

DEFINE_LOCAL_IRQ_LOCK(virtio_snd_tree_lock);
static DECLARE_PTREE(virtio_snd_tree);

enum {
    /* jack control request types */
    VIRTIO_SND_R_JACK_INFO = 1,
    VIRTIO_SND_R_JACK_REMAP,
    /* PCM control request types */
    VIRTIO_SND_R_PCM_INFO = 0x0100,
    VIRTIO_SND_R_PCM_SET_PARAMS,
    VIRTIO_SND_R_PCM_PREPARE,
    VIRTIO_SND_R_PCM_RELEASE,
    VIRTIO_SND_R_PCM_START,
    VIRTIO_SND_R_PCM_STOP,
    /* channel map control request types */
    VIRTIO_SND_R_CHMAP_INFO = 0x0200,
    /* jack event types */
    VIRTIO_SND_EVT_JACK_CONNECTED = 0x1000,
    VIRTIO_SND_EVT_JACK_DISCONNECTED,
    /* PCM event types */
    VIRTIO_SND_EVT_PCM_PERIOD_ELAPSED = 0x1100,
    VIRTIO_SND_EVT_PCM_XRUN,
    /* common status codes */
    VIRTIO_SND_S_OK = 0x8000,
    VIRTIO_SND_S_BAD_MSG,
    VIRTIO_SND_S_NOT_SUPP,
    VIRTIO_SND_S_IO_ERR
};

/* a common header */
struct virtio_snd_hdr {
    le32_t code;
} __packed;

struct virtio_snd_pcm_hdr {
    struct virtio_snd_hdr hdr;
    le32_t stream_id;
} __packed;

struct virtio_snd_info {
    le32_t hda_fn_nid;
} __packed;

/* an event notification */
struct virtio_snd_event {
    struct virtio_snd_hdr hdr;
    le32_t data;
} __packed;

enum {
    VIRTIO_SND_D_OUTPUT = 0,
    VIRTIO_SND_D_INPUT
};

struct virtio_snd_query_info {
    struct virtio_snd_hdr hdr;
    le32_t start_id;
    le32_t count;
    le32_t size;
};

struct virtio_snd_config {
    le32_t jacks;
    le32_t streams;
    le32_t chmaps;
} __packed;

/* supported PCM stream features */
enum {
    VIRTIO_SND_PCM_F_SHMEM_HOST = 0,
    VIRTIO_SND_PCM_F_SHMEM_GUEST,
    VIRTIO_SND_PCM_F_MSG_POLLING,
    VIRTIO_SND_PCM_F_EVT_SHMEM_PERIODS,
    VIRTIO_SND_PCM_F_EVT_XRUNS
};

/* supported PCM sample formats */
enum {
    /* analog formats (width / physical width) */
    VIRTIO_SND_PCM_FMT_IMA_ADPCM = 0, /* 4 / 4 bits */
    VIRTIO_SND_PCM_FMT_MU_LAW, /* 8 / 8 bits */
    VIRTIO_SND_PCM_FMT_A_LAW, /* 8 / 8 bits */
    VIRTIO_SND_PCM_FMT_S8, /* 8 / 8 bits */
    VIRTIO_SND_PCM_FMT_U8, /* 8 / 8 bits */
    VIRTIO_SND_PCM_FMT_S16, /* 16 / 16 bits */
    VIRTIO_SND_PCM_FMT_U16, /* 16 / 16 bits */
    VIRTIO_SND_PCM_FMT_S18_3, /* 18 / 24 bits */
    VIRTIO_SND_PCM_FMT_U18_3, /* 18 / 24 bits */
    VIRTIO_SND_PCM_FMT_S20_3, /* 20 / 24 bits */
    VIRTIO_SND_PCM_FMT_U20_3, /* 20 / 24 bits */
    VIRTIO_SND_PCM_FMT_S24_3, /* 24 / 24 bits */
    VIRTIO_SND_PCM_FMT_U24_3, /* 24 / 24 bits */
    VIRTIO_SND_PCM_FMT_S20, /* 20 / 32 bits */
    VIRTIO_SND_PCM_FMT_U20, /* 20 / 32 bits */
    VIRTIO_SND_PCM_FMT_S24, /* 24 / 32 bits */
    VIRTIO_SND_PCM_FMT_U24, /* 24 / 32 bits */
    VIRTIO_SND_PCM_FMT_S32, /* 32 / 32 bits */
    VIRTIO_SND_PCM_FMT_U32, /* 32 / 32 bits */
    VIRTIO_SND_PCM_FMT_FLOAT, /* 32 / 32 bits */
    VIRTIO_SND_PCM_FMT_FLOAT64, /* 64 / 64 bits */
    /* digital formats (width / physical width) */
    VIRTIO_SND_PCM_FMT_DSD_U8, /* 8 / 8 bits */
    VIRTIO_SND_PCM_FMT_DSD_U16, /* 16 / 16 bits */
    VIRTIO_SND_PCM_FMT_DSD_U32, /* 32 / 32 bits */
    VIRTIO_SND_PCM_FMT_IEC958_SUBFRAME /* 32 / 32 bits */
};

static inline const char *
virtio_snd_pcm_format_to_string(
        int format)
{
    switch(format) {
        case VIRTIO_SND_PCM_FMT_IMA_ADPCM: return "VIRTIO_SND_PCM_FMT_IMA_ADPCM";
        case VIRTIO_SND_PCM_FMT_MU_LAW: return "VIRTIO_SND_PCM_FMT_MU_LAW";
        case VIRTIO_SND_PCM_FMT_A_LAW: return "VIRTIO_SND_PCM_FMT_A_LAW";
        case VIRTIO_SND_PCM_FMT_S8: return "VIRTIO_SND_PCM_FMT_S8";
        case VIRTIO_SND_PCM_FMT_U8: return "VIRTIO_SND_PCM_FMT_U8";
        case VIRTIO_SND_PCM_FMT_S16: return "VIRTIO_SND_PCM_FMT_S16";
        case VIRTIO_SND_PCM_FMT_U16: return "VIRTIO_SND_PCM_FMT_U16";
        case VIRTIO_SND_PCM_FMT_S18_3: return "VIRTIO_SND_PCM_FMT_S18_3";
        case VIRTIO_SND_PCM_FMT_U18_3: return "VIRTIO_SND_PCM_FMT_U18_3";
        case VIRTIO_SND_PCM_FMT_S20_3: return "VIRTIO_SND_PCM_FMT_S20_3";
        case VIRTIO_SND_PCM_FMT_U20_3: return "VIRTIO_SND_PCM_FMT_U20_3";
        case VIRTIO_SND_PCM_FMT_S24_3: return "VIRTIO_SND_PCM_FMT_S24_3";
        case VIRTIO_SND_PCM_FMT_U24_3: return "VIRTIO_SND_PCM_FMT_U24_3";
        case VIRTIO_SND_PCM_FMT_S20: return "VIRTIO_SND_PCM_FMT_S20";
        case VIRTIO_SND_PCM_FMT_U20: return "VIRTIO_SND_PCM_FMT_U20";
        case VIRTIO_SND_PCM_FMT_S24: return "VIRTIO_SND_PCM_FMT_S24";
        case VIRTIO_SND_PCM_FMT_U24: return "VIRTIO_SND_PCM_FMT_U24";
        case VIRTIO_SND_PCM_FMT_S32: return "VIRTIO_SND_PCM_FMT_S32";
        case VIRTIO_SND_PCM_FMT_U32: return "VIRTIO_SND_PCM_FMT_U32";
        case VIRTIO_SND_PCM_FMT_FLOAT: return "VIRTIO_SND_PCM_FMT_FLOAT";
        case VIRTIO_SND_PCM_FMT_FLOAT64: return "VIRTIO_SND_PCM_FMT_FLOAT64";
        case VIRTIO_SND_PCM_FMT_DSD_U8: return "VIRTIO_SND_PCM_FMT_DSD_U8";
        case VIRTIO_SND_PCM_FMT_DSD_U16: return "VIRTIO_SND_PCM_FMT_DSD_U16";
        case VIRTIO_SND_PCM_FMT_DSD_U32: return "VIRTIO_SND_PCM_FMT_DSD_U32";
        case VIRTIO_SND_PCM_FMT_IEC958_SUBFRAME: return "VIRTIO_SND_PCM_FMT_IEC958_SUBFRAME";
        default: return "VIRTIO_SND_PCM_FMT_INVALID";
    }
}

static inline int
virtio_snd_pcm_format_sample_size(
        int format)
{
    switch(format) {
        case VIRTIO_SND_PCM_FMT_S8:
            return 1;
        case VIRTIO_SND_PCM_FMT_U8:
            return 1;
        case VIRTIO_SND_PCM_FMT_S16:
            return 2;
        case VIRTIO_SND_PCM_FMT_U16:
            return 2;
        case VIRTIO_SND_PCM_FMT_S32:
            return 4;
        case VIRTIO_SND_PCM_FMT_U32:
            return 4;
        case VIRTIO_SND_PCM_FMT_FLOAT:
            return 4;
        case VIRTIO_SND_PCM_FMT_FLOAT64:
            return 8;

        case VIRTIO_SND_PCM_FMT_IMA_ADPCM:
        case VIRTIO_SND_PCM_FMT_MU_LAW:
        case VIRTIO_SND_PCM_FMT_A_LAW:
        case VIRTIO_SND_PCM_FMT_S18_3:
        case VIRTIO_SND_PCM_FMT_U18_3:
        case VIRTIO_SND_PCM_FMT_S20_3:
        case VIRTIO_SND_PCM_FMT_U20_3:
        case VIRTIO_SND_PCM_FMT_S24_3:
        case VIRTIO_SND_PCM_FMT_U24_3:
        case VIRTIO_SND_PCM_FMT_S20:
        case VIRTIO_SND_PCM_FMT_U20:
        case VIRTIO_SND_PCM_FMT_S24:
        case VIRTIO_SND_PCM_FMT_U24:
        case VIRTIO_SND_PCM_FMT_DSD_U8:
        case VIRTIO_SND_PCM_FMT_DSD_U16:
        case VIRTIO_SND_PCM_FMT_DSD_U32:
        case VIRTIO_SND_PCM_FMT_IEC958_SUBFRAME:
            return -EUNIMPL;

        default:
            return -EINVAL;
    }
}

/* supported PCM frame rates */
enum {
    VIRTIO_SND_PCM_RATE_5512 = 0,
    VIRTIO_SND_PCM_RATE_8000,
    VIRTIO_SND_PCM_RATE_11025,
    VIRTIO_SND_PCM_RATE_16000,
    VIRTIO_SND_PCM_RATE_22050,
    VIRTIO_SND_PCM_RATE_32000,
    VIRTIO_SND_PCM_RATE_44100,
    VIRTIO_SND_PCM_RATE_48000,
    VIRTIO_SND_PCM_RATE_64000,
    VIRTIO_SND_PCM_RATE_88200,
    VIRTIO_SND_PCM_RATE_96000,
    VIRTIO_SND_PCM_RATE_176400,
    VIRTIO_SND_PCM_RATE_192000,
    VIRTIO_SND_PCM_RATE_384000
};

static inline hz_t
virtio_snd_pcm_rate_to_hz(
        unsigned int rate)
{
    switch(rate) {
        case VIRTIO_SND_PCM_RATE_5512:    return 5512;
        case VIRTIO_SND_PCM_RATE_8000:    return 8000;
        case VIRTIO_SND_PCM_RATE_11025:   return 11025;
        case VIRTIO_SND_PCM_RATE_16000:   return 16000;
        case VIRTIO_SND_PCM_RATE_22050:   return 22050;
        case VIRTIO_SND_PCM_RATE_32000:   return 32000;
        case VIRTIO_SND_PCM_RATE_44100:   return 44100;
        case VIRTIO_SND_PCM_RATE_48000:   return 48000;
        case VIRTIO_SND_PCM_RATE_64000:   return 64000;
        case VIRTIO_SND_PCM_RATE_88200:   return 88200;
        case VIRTIO_SND_PCM_RATE_96000:   return 96000;
        case VIRTIO_SND_PCM_RATE_176400:  return 176400;
        case VIRTIO_SND_PCM_RATE_192000:  return 192000;
        case VIRTIO_SND_PCM_RATE_384000:  return 384000;
        default: return 0;
    }
}

struct virtio_snd_pcm_info {
    struct virtio_snd_info hdr;
    le32_t features; /* 1 << VIRTIO_SND_PCM_F_XXX */
    le64_t formats; /* 1 << VIRTIO_SND_PCM_FMT_XXX */
    le64_t rates; /* 1 << VIRTIO_SND_PCM_RATE_XXX */
    uint8_t direction;
    uint8_t channels_min;
    uint8_t channels_max;
    uint8_t padding[5];
} __packed;

struct virtio_snd_pcm_set_params {
    struct virtio_snd_pcm_hdr hdr; /* .code = VIRTIO_SND_R_PCM_SET_PARAMS */
    le32_t buffer_bytes;
    le32_t period_bytes;
    le32_t features; /* 1 << VIRTIO_SND_PCM_F_XXX */
    uint8_t channels;
    uint8_t format;
    uint8_t rate;
    uint8_t padding;
} __packed;

struct virtio_snd_pcm_xfer {
    le32_t stream_id;
} __packed;
/* an I/O status */
struct virtio_snd_pcm_status {
    le32_t status;
    le32_t latency_bytes;
} __packed;

//
struct virtio_snd
{
    struct virtio_device *virtio_dev;

    struct ptree_node pnode;

    struct virtio_queue *control_queue;
    struct virtio_queue *event_queue;
    struct virtio_queue *xmit_queue;
    struct virtio_queue *recv_queue;

    uint32_t num_jacks;
    uint32_t num_streams;
    uint32_t num_chmaps;

    struct thread_lock stream_tree_lock;
    struct ptree stream_tree;
};

struct virtio_snd_stream {
    size_t index;
    struct virtio_snd *snd;
    struct ptree_node pnode;

    struct snd_dev snd_dev;

    uint32_t features_bitmap;
    uint64_t format_bitmap;
    uint64_t rate_bitmap;
    uint8_t direction;
    uint8_t channels_min;
    uint8_t channels_max;

    size_t num_formats;
    size_t num_rates;
    size_t num_modes;

    irq_lock_t buffer_lock;
    uint32_t buffer_bytes;
    uint32_t content_bytes;
    void *buffer;

    struct irq_lock mode_lock;
    size_t cur_mode;
    int started;
    int sample_size;

#define VIRTIO_SND_STREAM_NAME_BUFLEN 32
    char namebuf[VIRTIO_SND_STREAM_NAME_BUFLEN];
};

static int
virtio_snd_probe(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    int res;
    printk("virtio_snd_probe\n");
    return 0;
}

static int
virtio_snd_negotiate(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    int res;
    printk("virtio_snd_negotiate\n");
    return 0;
}

static int
virtio_snd_stream_mode_pcm_info(
        struct virtio_snd_stream *stream,
        size_t mode,
        unsigned int *format,
        unsigned int *rate)
{
    size_t format_index = mode % stream->num_formats;
    size_t rate_index = mode / stream->num_formats;

    uint64_t format_bitmap = stream->format_bitmap;
    uint64_t rate_bitmap = stream->rate_bitmap;
    while(format_index > 0) {
        DEBUG_ASSERT(format_bitmap != 0);
        format_bitmap &= ~(1UL<<(63-__builtin_clzl((unsigned long)format_bitmap)));
        format_index--;
    }
    DEBUG_ASSERT(format_bitmap != 0);
    while(rate_index > 0) {
        DEBUG_ASSERT(rate_bitmap != 0);
        rate_bitmap &= ~(1UL<<(63-__builtin_clzl((unsigned long)rate_bitmap)));
        rate_index--;
    }
    DEBUG_ASSERT(rate_bitmap != 0);

    size_t format_bit = 63-__builtin_clzl((unsigned long)format_bitmap);
    size_t rate_bit = 63-__builtin_clzl((unsigned long)rate_bitmap);

    *format = format_bit;
    *rate = rate_bit;

    return 0;
}

static int
virtio_snd_stream_start_lockless(
        struct virtio_snd_stream *stream)
{
    int res;

    if(stream->started) {
        return 0;
    }

    struct virtio_snd_pcm_hdr req = {
        .hdr.code = htole32(VIRTIO_SND_R_PCM_START),
        .stream_id = htole32(stream->index),
    };
    struct virtio_snd_hdr resp;

    res = virtio_transact_1_1(
            stream->snd->control_queue,
            &req,
            sizeof(req),
            &resp,
            sizeof(resp));
    if(res) {
        wprintk("virtio-snd: Failed to start stream!\n");
        return res;
    }

    if(letoh32(resp.code) != VIRTIO_SND_S_OK) {
        wprintk("virtio-snd: Failed to start stream!\n");
        return res;
    }

    return 0;
}
static int
virtio_snd_stream_stop_lockless(
        struct virtio_snd_stream *stream)
{
    int res;

    if(!stream->started) {
        return 0;
    }

    struct virtio_snd_pcm_hdr req = {
        .hdr.code = htole32(VIRTIO_SND_R_PCM_STOP),
        .stream_id = htole32(stream->index),
    };
    struct virtio_snd_hdr resp;

    res = virtio_transact_1_1(
            stream->snd->control_queue,
            &req,
            sizeof(req),
            &resp,
            sizeof(resp));
    if(res) {
        wprintk("virtio-snd: Failed to stop stream!\n");
        return res;
    }

    if(letoh32(resp.code) != VIRTIO_SND_S_OK) {
        wprintk("virtio-snd: Failed to stop stream!\n");
        return res;
    }

    return 0;
}

static int
virtio_snd_stream_prepare_lockless(
        struct virtio_snd_stream *stream)
{
    int res;

    struct virtio_snd_pcm_hdr req = {
        .hdr.code = htole32(VIRTIO_SND_R_PCM_PREPARE),
        .stream_id = htole32(stream->index),
    };
    struct virtio_snd_hdr resp;

    res = virtio_transact_1_1(
            stream->snd->control_queue,
            &req,
            sizeof(req),
            &resp,
            sizeof(resp));
    if(res) {
        wprintk("virtio-snd: Failed to prepare stream!\n");
        return res;
    }

    if(letoh32(resp.code) != VIRTIO_SND_S_OK) {
        wprintk("virtio-snd: Failed to prepare stream!\n");
        return res;
    }

    return 0;
}

__maybe_unused
static int
virtio_snd_stream_release_lockless(
        struct virtio_snd_stream *stream)
{
    int res;

    struct virtio_snd_pcm_hdr req = {
        .hdr.code = htole32(VIRTIO_SND_R_PCM_RELEASE),
        .stream_id = htole32(stream->index),
    };
    struct virtio_snd_hdr resp;

    res = virtio_transact_1_1(
            stream->snd->control_queue,
            &req,
            sizeof(req),
            &resp,
            sizeof(resp));
    if(res) {
        wprintk("virtio-snd: Failed to release stream!\n");
        return res;
    }

    if(letoh32(resp.code) != VIRTIO_SND_S_OK) {
        wprintk("virtio-snd: Failed to release stream!\n");
        return res;
    }

    return 0;
}

static int
virtio_snd_stream_set_mode(
        struct virtio_snd_stream *stream,
        size_t mode)
{
    int res;

    if(mode >= stream->num_modes) {
        return -EINVAL;
    }

    irq_lock_acquire(&stream->mode_lock);

    res = virtio_snd_stream_stop_lockless(stream);
    if(res) {
        irq_lock_release(&stream->mode_lock);
        return res;
    }

    unsigned int pcm_format, pcm_rate;
    virtio_snd_stream_mode_pcm_info(stream, mode, &pcm_format, &pcm_rate);

    printk("virtio-snd: Stream(%d) setting mode(%lu) with format=\"%s\", rate=%lu (f=%ld,r=%ld)\n",
            (int)stream->index,
            (ul_t)mode,
            virtio_snd_pcm_format_to_string(pcm_format),
            (ul_t)virtio_snd_pcm_rate_to_hz(pcm_rate),
            (sl_t)pcm_format, (sl_t)pcm_rate);

    struct virtio_snd_pcm_set_params req = {
        .hdr.hdr.code = VIRTIO_SND_R_PCM_SET_PARAMS,
        .hdr.stream_id = htole32(stream->index),
        .rate = pcm_rate,
        .format = pcm_format,
        .channels = 1,
        .features = 0,
        .buffer_bytes = htole32(stream->buffer_bytes),
        .period_bytes = htole32(stream->buffer_bytes),
    };
    struct virtio_snd_hdr resp;

    res = virtio_transact_1_1(
            stream->snd->control_queue,
            &req,
            sizeof(req),
            &resp,
            sizeof(resp));
    if(res) {
        irq_lock_release(&stream->mode_lock);
        wprintk("virtio-snd: failed to run virtio transaction to set up stream parameters! (err=%s)\n",
                errnostr(res));
        return res;
    }

    if(letoh32(resp.code) != VIRTIO_SND_S_OK) {
        wprintk("virtio-snd: Request to set stream parameters failed!\n");
        irq_lock_release(&stream->mode_lock);
        return -EFAULT;
    }

    stream->cur_mode = mode;
    stream->sample_size = virtio_snd_pcm_format_sample_size(pcm_format);

    res = virtio_snd_stream_start_lockless(stream);
    if(res) {
        irq_lock_release(&stream->mode_lock);
        return res;
    }

    irq_lock_release(&stream->mode_lock);

    return 0;
}

static ssize_t
virtio_snd_dev_get_mode(
        struct snd_dev *snd)
{
    struct virtio_snd_stream *stream =
        container_of(snd, struct virtio_snd_stream, snd_dev);

    dprintk("virtio_snd_dev_get_mode\n");

    return stream->cur_mode;
}

static int
virtio_snd_dev_set_mode(
        struct snd_dev *snd,
        size_t mode)
{
    struct virtio_snd_stream *stream =
        container_of(snd, struct virtio_snd_stream, snd_dev);

    dprintk("virtio_snd_dev_set_mode\n");

    return virtio_snd_stream_set_mode(stream, mode);
}

static struct snd_mode_info *
virtio_snd_dev_get_mode_info(
        struct snd_dev *snd,
        size_t mode)
{
    struct virtio_snd_stream *stream =
        container_of(snd, struct virtio_snd_stream, snd_dev);

    dprintk("virtio_snd_dev_get_mode_info\n");

    if(mode >= stream->num_modes) {
        return NULL;
    }

    struct snd_mode_info *info = kzmalloc(sizeof(*info), KM_KERNEL);
    if(info == NULL) {
        return NULL;
    }

    unsigned int pcm_format;
    unsigned int pcm_rate;

    virtio_snd_stream_mode_pcm_info(
            stream,
            mode,
            &pcm_format,
            &pcm_rate);

    unsigned long hz = (unsigned long)virtio_snd_pcm_rate_to_hz(pcm_rate);

    info->sampling_hz = pcm_rate;
    switch(pcm_format)
    {
        case VIRTIO_SND_PCM_FMT_S8:
            info->format = SND_FORMAT_PCM_S8;
            break;
        case VIRTIO_SND_PCM_FMT_S16:
            info->format = SND_FORMAT_PCM_S16;
            break;
        case VIRTIO_SND_PCM_FMT_S32:
            info->format = SND_FORMAT_PCM_S32;
            break;
        case VIRTIO_SND_PCM_FMT_U8:
            info->format = SND_FORMAT_PCM_U8;
            break;
        case VIRTIO_SND_PCM_FMT_U16:
            info->format = SND_FORMAT_PCM_U16;
            break;
        case VIRTIO_SND_PCM_FMT_U32:
            info->format = SND_FORMAT_PCM_U32;
            break;

        case VIRTIO_SND_PCM_FMT_FLOAT:
            info->format = SND_FORMAT_PCM_FLOAT32;
            break;
        case VIRTIO_SND_PCM_FMT_FLOAT64:
            info->format = SND_FORMAT_PCM_FLOAT64;
            break;

        // Unimplemented
        case VIRTIO_SND_PCM_FMT_IMA_ADPCM:
        case VIRTIO_SND_PCM_FMT_MU_LAW:
        case VIRTIO_SND_PCM_FMT_A_LAW:
        case VIRTIO_SND_PCM_FMT_S18_3:
        case VIRTIO_SND_PCM_FMT_U18_3:
        case VIRTIO_SND_PCM_FMT_S20_3:
        case VIRTIO_SND_PCM_FMT_U20_3:
        case VIRTIO_SND_PCM_FMT_S24_3:
        case VIRTIO_SND_PCM_FMT_U24_3:
        case VIRTIO_SND_PCM_FMT_S20:
        case VIRTIO_SND_PCM_FMT_U20:
        case VIRTIO_SND_PCM_FMT_S24:
        case VIRTIO_SND_PCM_FMT_U24:
        case VIRTIO_SND_PCM_FMT_DSD_U8:
        case VIRTIO_SND_PCM_FMT_DSD_U16:
        case VIRTIO_SND_PCM_FMT_DSD_U32:
        case VIRTIO_SND_PCM_FMT_IEC958_SUBFRAME:
        default: {
            kfree(info);
            return NULL;
        }
    }

    info->volume_format = SND_VOLUME_FORMAT_BINARY;
    info->volume_min = 0;
    info->volume_max = 1;

    return info;
}

static int
virtio_snd_dev_put_mode_info(
        struct snd_dev *snd,
        size_t mode,
        struct snd_mode_info *info)
{
    struct virtio_snd_stream *stream =
        container_of(snd, struct virtio_snd_stream, snd_dev);

    DEBUG_ASSERT(KERNEL_ADDR(info));
    DEBUG_ASSERT(mode < stream->num_modes);

    dprintk("virtio_snd_dev_put_mode_info\n");

    kfree(info);
    return 0;
}

static int
virtio_snd_stream_flush_full_buffer_lockless(
        struct virtio_snd_stream *stream)
{
    int res;

    DEBUG_ASSERT(stream->buffer_bytes == stream->content_bytes);

    struct virtio_snd_pcm_xfer req = {
        .stream_id = htole32(stream->index),
    };
    struct virtio_snd_pcm_status resp;

    void *input_datas[] = {
        &req,
        stream->buffer,
    };
    size_t input_sizes[] = {
        sizeof(req),
        stream->buffer_bytes,
    };
    void *output_datas[] = {
        &resp,
    };
    size_t output_sizes[] = {
        sizeof(resp),
    };

    res = virtio_transact(
            stream->snd->xmit_queue,
            2,
            input_datas,
            input_sizes,
            1,
            output_datas,
            output_sizes);
    if(res) {
        DEBUG_ASSERT(res < 0);
        return res;
    }

    if(letoh32(resp.status) != VIRTIO_SND_S_OK) {
        return -EFAULT;
    }

    stream->content_bytes = 0;

    return 0;
}

static ssize_t
virtio_snd_dev_write_samples(
        struct snd_dev *snd,
        void *buffer,
        size_t buflen,
        unsigned long flags)
{
    int res;

    struct virtio_snd_stream *stream =
        container_of(snd, struct virtio_snd_stream, snd_dev);

    dprintk("virtio_snd_dev_write_samples (buflen=0x%lx)\n", buflen);

    if(stream->sample_size <= 0 || buflen < stream->sample_size) {
        return -EINVAL;
    }
    // Round down to a multiple of the sample size
    buflen -= (buflen % stream->sample_size);

    irq_lock_acquire(&stream->buffer_lock);

    size_t room_left = stream->buffer_bytes - stream->content_bytes;
    if(room_left == 0) {
        // The buffer needs to be written
        if(flags & SND_DEV_WRITE_SAMPLES_NON_BLOCKING) {
            return -EWOULDBLOCK;
        }
        res = virtio_snd_stream_flush_full_buffer_lockless(stream);
        if(res) {
            irq_lock_release(&stream->buffer_lock);
        }
        room_left = stream->buffer_bytes - stream->content_bytes;
    }

    size_t to_write = room_left < buflen ? room_left : buflen;
    memcpy(stream->buffer + stream->content_bytes,
           buffer,
           to_write);
    stream->content_bytes += to_write;

    if(stream->content_bytes == stream->buffer_bytes) {
        if(!(flags & SND_DEV_WRITE_SAMPLES_NON_BLOCKING)) {
            virtio_snd_stream_flush_full_buffer_lockless(stream);
        } else {
            // TODO: The might just leave bytes buffered here forever
            // towards the end of a stream,
            // the buffer is only about a page (a couple of microseconds of
            // sound data at the most) so that's not a huge deal,
            // but it is worth looking into.
        }
    }

    irq_lock_release(&stream->buffer_lock);

    return to_write;
}

static struct snd_driver
virtio_snd_stream_snd_driver = {
    .get_mode = virtio_snd_dev_get_mode,
    .set_mode = virtio_snd_dev_set_mode,
    .get_mode_info = virtio_snd_dev_get_mode_info,
    .put_mode_info = virtio_snd_dev_put_mode_info,
    .write_samples = virtio_snd_dev_write_samples,
};

static int
virtio_snd_init_stream(
        struct virtio_snd *snd,
        size_t stream_id)
{
    int res;

    struct virtio_snd_stream *stream;
    stream = kzmalloc(sizeof(*stream), KM_KERNEL);
    if(stream == NULL) {
        return -ENOMEM;
    }
    stream->index = stream_id;
    stream->snd = snd;

    irq_lock_init(&stream->buffer_lock);
    stream->buffer_bytes = VIRTIO_SND_STREAM_BUFLEN;
    stream->buffer = kzmalloc(stream->buffer_bytes, KM_KERNEL);
    if(stream->buffer == NULL) {
        kfree(stream);
        return -ENOMEM;
    }

    irq_lock_init(&stream->mode_lock);
    stream->cur_mode = -1;
    stream->started = 0;

    snprintk(stream->namebuf, VIRTIO_SND_STREAM_NAME_BUFLEN,
            "virtio-snd-%lu-%lu",
            (ul_t)snd->pnode.key,
            (ul_t)stream->index);

    { // Query the stream info
        struct virtio_snd_query_info query_info;
        struct virtio_snd_hdr hdr;
        struct virtio_snd_pcm_info pcm_info;
        void *input_datas[] = {
            &query_info,
        };
        size_t input_sizes[] = {
            sizeof(query_info),
        };
        void *output_datas[] = {
            &hdr,
            &pcm_info,
        };
        size_t output_sizes[] = {
            sizeof(hdr),
            sizeof(pcm_info),
        };

        query_info.hdr.code = htole32(VIRTIO_SND_R_PCM_INFO);
        query_info.start_id = htole32(stream_id);
        query_info.count = htole32(1);
        query_info.size = htole32(sizeof(pcm_info));

        res = virtio_transact(
                snd->control_queue,
                sizeof(input_datas)/sizeof(input_datas[0]),
                input_datas,
                input_sizes,
                sizeof(output_datas)/sizeof(output_datas[0]),
                output_datas,
                output_sizes);
        if(res) {
            kfree(stream->buffer);
            kfree(stream);
            wprintk("virtio-snd: Failed to query stream %d's information!\n",
                    (int)stream_id);
            return res;
        }
        if(letoh32(hdr.code) != VIRTIO_SND_S_OK) {
            kfree(stream->buffer);
            kfree(stream);
            wprintk("virtio-snd: Failed to query stream %d's information!\n",
                    (int)stream_id);
            return -EFAULT;
        }

        stream->features_bitmap = letoh32(pcm_info.features);
        stream->format_bitmap = letoh64(pcm_info.formats);
        stream->rate_bitmap = letoh64(pcm_info.rates);
        stream->direction = pcm_info.direction;
        stream->channels_min = pcm_info.channels_min;
        stream->channels_max = pcm_info.channels_max;

        printk("virtio-snd: Stream(%d)\n"
               "\tFeatures(0x%lx)\n"
               "\tFormats(0x%lx)\n"
               "\tRate(0x%lx)\n"
               "\tDirection(%s)\n"
               "\tChannel-Range[%d-%d]\n",
               (int)stream_id,
               (ul_t)stream->features_bitmap,
               (ul_t)stream->format_bitmap,
               (ul_t)stream->rate_bitmap,
                 stream->direction == VIRTIO_SND_D_INPUT ?  "INPUT"
               : stream->direction == VIRTIO_SND_D_OUTPUT ? "OUTPUT"
               : "INVALID",
               (int)stream->channels_min,
               (int)stream->channels_max
              );

        stream->num_formats = __builtin_popcountl(stream->format_bitmap);
        stream->num_rates = __builtin_popcountl(stream->rate_bitmap); 
        stream->num_modes = stream->num_formats * stream->num_rates;

//        for(size_t i = 0; i < stream->num_modes; i++) {
//            unsigned int pcm_format, pcm_rate;
//            virtio_snd_stream_mode_pcm_info(stream, i, &pcm_format, &pcm_rate);
//            printk("virtio-snd: Stream(%d) mode(%lu) has format=\"%s\", rate=%lu\n",
//                (int)stream->index,
//                (ul_t)i,
//                virtio_snd_pcm_format_to_string(pcm_format),
//                (ul_t)virtio_snd_pcm_rate_to_hz(pcm_rate),
//                (sl_t)pcm_format, (sl_t)pcm_rate);
//        }
    }

    {
        res = virtio_snd_stream_prepare_lockless(stream);
        if(res) {
            kfree(stream->buffer);
            kfree(stream);
            return res;
        }

        size_t starting_mode = 25;
        if(starting_mode >= stream->num_modes) {
            starting_mode = 0;
        }
        res = virtio_snd_stream_set_mode(stream, starting_mode);
        if(res) {
            kfree(stream->buffer);
            kfree(stream);
            return res;
        }
    }

    thread_lock_acquire(&snd->stream_tree_lock);
    ptree_insert(&snd->stream_tree, &stream->pnode, stream_id);
    thread_lock_release(&snd->stream_tree_lock);

    {
        stream->snd_dev.driver = &virtio_snd_stream_snd_driver;
        res = register_snd_dev(&stream->snd_dev, stream->namebuf);
        if(res) {
            wprintk("Failed to register virtio stream as a snd_dev! (err=%s)\n",
                    errnostr(res));
        }
    }

    return 0;
}

__maybe_unused
static int
virtio_snd_deinit_stream(
        struct virtio_snd *snd,
        size_t stream_id)
{
    thread_lock_acquire(&snd->stream_tree_lock);
    struct ptree_node *pnode = ptree_remove(&snd->stream_tree, stream_id);
    thread_lock_release(&snd->stream_tree_lock);
    if(pnode == NULL) {
        return -EINVAL;
    }
    struct virtio_snd_stream *stream;
    stream = container_of(pnode, struct virtio_snd_stream, pnode);

    DEBUG_ASSERT(stream->index == stream_id);

    kfree(stream->buffer);
    kfree(stream);

    return 0;
}

static int
virtio_snd_init_device(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    int res;
    printk("virtio_snd_init_device\n");

    if(device->num_queues < 4) {
        wprintk("virtio-snd: Found virtio-snd device with an incorrect number of queues! (found=%d, required=4)\n",
                (int)device->num_queues);
        return -EINVAL;
    }

    struct virtio_snd *snd = kzmalloc(sizeof(*snd), KM_KERNEL);
    if(snd == NULL) {
        return -ENOMEM;
    }
    snd->virtio_dev = device;

    thread_lock_init(&snd->stream_tree_lock);
    ptree_init(&snd->stream_tree);

    virtio_snd_tree_lock_acquire();
    ptree_insert_any(&virtio_snd_tree, &snd->pnode);
    virtio_snd_tree_lock_release();

    snd->control_queue = device->queues[0];
    snd->event_queue = device->queues[1];
    snd->xmit_queue = device->queues[2];
    snd->recv_queue = device->queues[3];

    virtio_queue_enable(snd->control_queue);
    virtio_queue_enable(snd->event_queue);
    virtio_queue_enable(snd->xmit_queue);
    virtio_queue_enable(snd->recv_queue);

    virtio_device_cfg_readl(device, 0, &snd->num_jacks);
    snd->num_jacks = letoh32(snd->num_jacks);
    virtio_device_cfg_readl(device, 4, &snd->num_streams);
    snd->num_streams = letoh32(snd->num_streams);
    virtio_device_cfg_readl(device, 8, &snd->num_chmaps);
    snd->num_chmaps = letoh32(snd->num_chmaps);

    printk("virtio-snd: (num-jacks=0x%lx) (num-streams=0x%lx) (num-chmaps=0x%lx)\n",
            (ul_t)snd->num_jacks,
            (ul_t)snd->num_streams,
            (ul_t)snd->num_chmaps);

    for(size_t stream_id = 0; stream_id < snd->num_streams; stream_id++) {
        res = virtio_snd_init_stream(
                snd,
                stream_id);
        if(res) {
            wprintk("virtio-snd: Failed to initialize stream: %d\n", (int)stream_id);
        }
    }

    return 0;
}

static int
virtio_snd_deinit_device(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    return -EUNIMPL;
}

static struct virtio_driver_ops
virtio_snd_virtio_driver_ops = {
    .probe = virtio_snd_probe,
    .negotiate = virtio_snd_negotiate,
    .init_device = virtio_snd_init_device,
    .deinit_device = virtio_snd_deinit_device,
};

static uint16_t
virtio_snd_virtio_ids[] = {
    25,
};

static struct virtio_driver
virtio_snd_virtio_driver = {
    .ops = &virtio_snd_virtio_driver_ops,
    .num_ids = sizeof(virtio_snd_virtio_ids) / sizeof(uint16_t),
    .ids = virtio_snd_virtio_ids,
};

static int
register_virtio_snd_driver(void)
{
    return register_virtio_driver(&virtio_snd_virtio_driver);
}
declare_init_desc(device, register_virtio_snd_driver, "Registered Virtio Sound Driver");
