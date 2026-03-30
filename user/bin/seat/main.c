
#include <fcntl.h>
#include <getopt.h>
#include <kanawha/file.h>
#include <kanawha/input.h>
#include <kanawha/udrv.h>
#include <kanawha/udrv/fb.h>
#include <kanawha/udrv/input.h>
#include <kfb/kfb.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct input
{
    int fd;
};

struct seat
{
    int udrv_fb;
    int udrv_input;

    size_t backing_mode;
    struct fb_mode_info *mode_info;
    struct kfb_framebuffer *backing_fb;
    struct input *backing_input;
};

static struct input *
open_input(const char *path)
{
    struct input *input = malloc(sizeof(*input));
    if(input == NULL)
    {
        perror("malloc");
        return NULL;
    }

    int fd = open(path, O_RDWR | O_NONBLOCK);
    if(fd < 0)
    {
        perror("open");
        return NULL;
    }

    input->fd = fd;

    return input;
}

static int
close_input(struct input *input)
{
    close(input->fd);
    free(input);
    return 0;
}

static inline int
mkudrv(const char *type, const char *name)
{
#define UDRV_PATH "/sys/udrv/"
#define PATHBUFLEN 256
    static char path[PATHBUFLEN];
    snprintf(path, PATHBUFLEN, "%s/%s/%s", UDRV_PATH, type, name);
    path[PATHBUFLEN - 1] = '\0';

    int fd = open(path, O_CREAT | O_RDWR | O_NONBLOCK, S_IRWXU);
    if(fd < 0)
    {
        fprintf(stderr, "Failed to create udrv device!\n");
        exit(-1);
    }

    return fd;

#undef UDRV_PATH
#undef PATHBUFLEN
}

static struct seat *
create_seat(const char *name,
            struct kfb_framebuffer *backing_fb,
            size_t backing_mode,
            struct input *backing_input)
{
    struct seat *seat = malloc(sizeof(struct seat));
    if(seat == NULL)
    {
        perror("malloc");
        return NULL;
    }
    seat->udrv_fb = mkudrv("fb", name);
    seat->udrv_input = mkudrv("input", name);

    seat->backing_fb = backing_fb;
    seat->backing_input = backing_input;
    seat->backing_mode = backing_mode;

    seat->mode_info = kfb_load_mode_info(backing_fb, backing_mode);

    {
#define PKT_BUFLEN FILE_READ_MAX_BUFSIZE
        static char pkt_buffer[PKT_BUFLEN];
        struct udrv_pkt *udrv_pkt = (void *)pkt_buffer;
        udrv_pkt->type = UDRV_FB_PKT_PROVIDE_MODE_INFO;
        udrv_pkt->flags = 0;

        struct udrv_fb_pkt_provide_mode_info *pkt = (void *)&udrv_pkt->data;
        pkt->index = 0;

        size_t modelen =
            sizeof(struct fb_mode_info) +
            (sizeof(struct fb_layer_info) * seat->mode_info->layer_count);
        memcpy(&pkt->mode_info, seat->mode_info, modelen);

        size_t pktlen =
            sizeof(struct udrv_pkt) +
            sizeof(struct udrv_fb_pkt_provide_mode_info) +
            (sizeof(struct fb_layer_info) * seat->mode_info->layer_count);

        write(seat->udrv_fb, udrv_pkt, pktlen);
#undef PKT_BUFLEN
    }

    return seat;
};

static int
suspend_seat(struct seat *seat)
{
    {
        struct udrv_pkt pkt;
        pkt.type = UDRV_FB_PKT_MASK_WRITES;
        pkt.flags = 0;
        write(seat->udrv_fb, (void *)&pkt, sizeof(pkt));
    }
    {
        struct udrv_pkt pkt;
        pkt.type = UDRV_FB_PKT_NOTIFY_DATA_LOST;
        pkt.flags = 0;
        write(seat->udrv_fb, (void *)&pkt, sizeof(pkt));
    }
}

static int
resume_seat(struct seat *seat)
{
    kfb_set_current_mode(seat->backing_fb, seat->backing_mode);
    struct udrv_pkt pkt;
    pkt.type = UDRV_FB_PKT_UNMASK_WRITES;
    pkt.flags = 0;
    write(seat->udrv_fb, (void *)&pkt, sizeof(pkt));
}

static inline int
seat_handle_framebuffer_set_mode(struct seat *seat,
                                 struct udrv_pkt *udrv_pkt,
                                 size_t pktlen)
{
    struct udrv_fb_pkt_set_mode *pkt = (void *)&udrv_pkt->data;
    size_t datalen = pktlen - sizeof(struct udrv_pkt);

    // TODO
    // printf("seat_handle_framebuffer_set_mode\n");

    return 0;
}

static inline int
seat_handle_framebuffer_write_to_buffer(struct seat *seat,
                                        struct udrv_pkt *udrv_pkt,
                                        size_t pktlen)
{
    int res;

    struct udrv_fb_pkt_write_to_buffer *pkt = (void *)&udrv_pkt->data;
    size_t max_datalen = pktlen + (-sizeof(struct udrv_pkt)) +
                         (-sizeof(struct udrv_fb_pkt_write_to_buffer));
    void *data = pkt->data;

    size_t offset = pkt->offset;
    size_t datalen = pkt->datalen;

    if(datalen > max_datalen)
    {
        fprintf(stderr,
                "seat_handle_framebuffer_write_to_buffer invalid datalen! "
                "(offset=0x%lx, datalen=0x%lx, maxdatalen=0x%lx)\n",
                (unsigned long)offset,
                (unsigned long)datalen,
                (unsigned long)max_datalen);
        datalen = max_datalen;
    }

    //    printf("seat_handle_framebuffer_write_to_buffer (offset=0x%lx,
    //    datalen=0x%lx)\n",
    //            (unsigned long)offset,
    //            (unsigned long)datalen
    //            );

    res = kfb_framebuffer_copy_direct(seat->backing_fb, offset, data, datalen);
    if(res)
    {
        fprintf(stderr,
                "seat_handle_framebuffer_write_to_buffer failed to "
                "copy data to framebuffer!\n");
        return res;
    }

    kfb_flush_framebuffer(seat->backing_fb);

    return 0;
}

static const char *progname = "seat";
static inline void
print_usage(void)
{
    fprintf(stderr, "%s INPUT FB\n", progname);
}
static inline void
panic_usage(void)
{
    print_usage();
    exit(-1);
}

int
main(int argc, const char **argv)
{
    if(argc > 0)
    {
        progname = argv[0];
    }

    const char *input_path = NULL;
    const char *fb_path = NULL;
    size_t num_seats = 0;

    {
        int opt;
        while((opt = getopt(argc, (char **)argv, "h")) != -1)
        {
            switch(opt)
            {
            // Handle Any Short Options
            case 'h':
                print_usage();
                return 0;
            default:
                panic_usage();
                break;
            }
        }
    }

    int *seat_modes = NULL;

    {
        int pos_argc = argc - optind;

        if(pos_argc < 0)
        {
            pos_argc = 0;
        }

        const char **pos_argv = argv + optind;

        if(pos_argc < 3)
        {
            panic_usage();
        }

        input_path = pos_argv[0];
        fb_path = pos_argv[1];

        num_seats = pos_argc - 2;
        seat_modes = malloc(sizeof(int) * num_seats);
        for(size_t i = 0; i < num_seats; i++)
        {
            seat_modes[i] = atoi(pos_argv[i + 2]);
        }
    }

    if(input_path == NULL)
    {
        panic_usage();
    }
    if(fb_path == NULL)
    {
        panic_usage();
    }

    struct kfb_framebuffer *framebuffer = kfb_open_framebuffer(fb_path);
    if(framebuffer == NULL)
    {
        fprintf(stderr, "Failed to open framebuffer \"%s\"!\n", fb_path);
        return -1;
    }

    struct input *input = open_input(input_path);
    if(input == NULL)
    {
        fprintf(stderr, "Failed to open input \"%s\"!\n", input_path);
        return -1;
    }

    struct seat **seats = malloc(sizeof(struct seat *) * num_seats);
    size_t current_seat = 0;

    for(size_t i = 0; i < num_seats; i++)
    {
        char *buffer = malloc(64);
        buffer[63] = '\0';

        snprintf(buffer, 64, "seat-%lu", (unsigned long)i);

        struct seat *seat =
            create_seat(buffer, framebuffer, seat_modes[i], input);

        suspend_seat(seat);

        seats[i] = seat;
    }

    int running = 1;

    int lctrl_is_pressed = 0;
    int rctrl_is_pressed = 0;

    resume_seat(seats[current_seat]);

    while(running)
    {
        struct input_event event;
        ssize_t amt_read =
            read(input->fd, (void *)&event, sizeof(struct input_event));
        size_t num_read = amt_read / sizeof(struct input_event);
        if(num_read == 1)
        {
            // Need to handle a input event
            if(event.key == INPUT_KEY_LCTRL)
            {
                lctrl_is_pressed = (event.motion != INPUT_MOTION_RELEASED);
            }
            if(event.key == INPUT_KEY_RCTRL)
            {
                rctrl_is_pressed = (event.motion != INPUT_MOTION_RELEASED);
            }
            if(lctrl_is_pressed || rctrl_is_pressed)
            {
                if(event.key == INPUT_KEY_TAB &&
                   event.motion == INPUT_MOTION_PRESSED)
                {
                    // cycle the current seat
                    printf("suspending seat %ld\n", (long)current_seat);
                    suspend_seat(seats[current_seat]);
                    current_seat++;
                    if(current_seat >= num_seats)
                    {
                        current_seat = 0;
                    }
                    printf("resuming seat %ld\n", (long)current_seat);
                    resume_seat(seats[current_seat]);
                    printf("setting seat to %ld\n", (long)current_seat);
                }
            }
            else
            {
#define BUFLEN (sizeof(struct udrv_pkt) + sizeof(struct input_event))
                char buffer[BUFLEN];
                struct udrv_pkt *pkt = (void *)&buffer;
                pkt->type = UDRV_INPUT_PKT_PROVIDE_INPUT;
                pkt->flags = 0;
                *(struct input_event *)pkt->data = event;
                write(seats[current_seat]->udrv_input, (void *)pkt, BUFLEN);
#undef BUFLEN
            }
        }

        // Read a packet from the kernel about this framebuffer
#define FB_PKT_BUFLEN FILE_READ_MAX_BUFSIZE
        static char buffer[FB_PKT_BUFLEN];
        ssize_t pktlen =
            read(seats[current_seat]->udrv_fb, buffer, FB_PKT_BUFLEN);
        if(pktlen > sizeof(struct udrv_pkt))
        {
            struct udrv_pkt *udrv_pkt = (void *)&buffer;
            switch(udrv_pkt->type)
            {
            case UDRV_FB_PKT_SET_MODE:
                seat_handle_framebuffer_set_mode(seats[current_seat],
                                                 udrv_pkt,
                                                 pktlen);
                break;
            case UDRV_FB_PKT_WRITE_TO_BUFFER:
                seat_handle_framebuffer_write_to_buffer(seats[current_seat],
                                                        udrv_pkt,
                                                        pktlen);
                break;
            default:
                fprintf(stderr,
                        "received unrecognized udrv framebuffer "
                        "packet "
                        "from the kernel!\n");
                break;
            }
        }
#undef FB_PKT_BUFLEN
    }

    return 0;
}
