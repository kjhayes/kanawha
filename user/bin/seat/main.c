
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <kfb/kfb.h>
#include <kanawha/kbd.h>
#include <kanawha/file.h>
#include <kanawha/udrv.h>
#include <kanawha/udrv/fb.h>
#include <kanawha/udrv/kbd.h>
#include <getopt.h>

struct kbd {
    int fd;
};

struct seat {
    int udrv_fb;
    int udrv_kbd;

    size_t backing_mode;
    struct fb_mode_info *mode_info;
    struct kfb_framebuffer *backing_fb;
    struct kbd *backing_kbd;
};

static struct kbd *
open_kbd(const char *path)
{
    struct kbd *kbd = malloc(sizeof(*kbd));
    if(kbd == NULL) {
	perror("malloc");
	return NULL;
    }

    int fd = open(path, O_RDWR|O_NONBLOCK);
    if(fd < 0) {
	perror("open");
	return NULL;
    }

    kbd->fd = fd;

    return kbd;
}

static int
close_kbd(struct kbd *kbd)
{
    close(kbd->fd);
    free(kbd);
    return 0;
}

static inline int
mkudrv(const char *type, const char *name)
{
#define UDRV_PATH "/sys/udrv/"
#define PATHBUFLEN 256
    static char path[PATHBUFLEN];
    snprintf(path, PATHBUFLEN, "%s/%s/%s",
	    UDRV_PATH,
	    type,
	    name
	    );
    path[PATHBUFLEN-1] = '\0';

    int fd = open(path, O_CREAT|O_RDWR|O_NONBLOCK, S_IRWXU);
    if(fd < 0) {
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
	    struct kbd *backing_kbd)
{
    struct seat *seat = malloc(sizeof(struct seat));
    if(seat == NULL) {
	perror("malloc");
	return NULL;
    }
    seat->udrv_fb  = mkudrv("fb", name);
    seat->udrv_kbd = mkudrv("kbd", name);

    seat->backing_fb = backing_fb;
    seat->backing_kbd = backing_kbd;
    seat->backing_mode = backing_mode;

    seat->mode_info = kfb_load_mode_info(backing_fb, backing_mode);

    {
#define PKT_BUFLEN FILE_READ_MAX_BUFSIZE
	static char pkt_buffer[PKT_BUFLEN];
	struct udrv_pkt *udrv_pkt = (void*)pkt_buffer;
	udrv_pkt->type = UDRV_FB_PKT_PROVIDE_MODE_INFO;
	udrv_pkt->flags = 0;

	struct udrv_fb_pkt_provide_mode_info *pkt = (void*)&udrv_pkt->data;
	pkt->index = 0;

	size_t modelen = sizeof(struct fb_mode_info) + (sizeof(struct fb_layer_info) * seat->mode_info->layer_count);
	memcpy(&pkt->mode_info, seat->mode_info, modelen);

	size_t pktlen = sizeof(struct udrv_pkt)
	             +  sizeof(struct udrv_fb_pkt_provide_mode_info)
		     + (sizeof(struct fb_layer_info) * seat->mode_info->layer_count);

	write(seat->udrv_fb, udrv_pkt, pktlen);
#undef PKT_BUFLEN
    }

    return seat;
};

static int
suspend_seat(
	struct seat *seat)
{
    {
    struct udrv_pkt pkt;
    pkt.type = UDRV_FB_PKT_MASK_WRITES;
    pkt.flags = 0;
    write(seat->udrv_fb, (void*)&pkt, sizeof(pkt));
    }
    {
    struct udrv_pkt pkt;
    pkt.type = UDRV_FB_PKT_NOTIFY_DATA_LOST;
    pkt.flags = 0;
    write(seat->udrv_fb, (void*)&pkt, sizeof(pkt));
    }
}

static int
resume_seat(
	struct seat *seat)
{
    kfb_set_current_mode(seat->backing_fb, seat->backing_mode);
    struct udrv_pkt pkt;
    pkt.type = UDRV_FB_PKT_UNMASK_WRITES;
    pkt.flags = 0;
    write(seat->udrv_fb, (void*)&pkt, sizeof(pkt));
}

static inline int
seat_handle_framebuffer_set_mode(
	struct seat *seat,
	struct udrv_pkt *udrv_pkt,
	size_t pktlen)
{
    struct udrv_fb_pkt_set_mode *pkt = (void*)&udrv_pkt->data;
    size_t datalen = pktlen - sizeof(struct udrv_pkt);

    // TODO
    //printf("seat_handle_framebuffer_set_mode\n");

    return 0;
}

static inline int
seat_handle_framebuffer_write_to_buffer(
	struct seat *seat,
	struct udrv_pkt *udrv_pkt,
	size_t pktlen)
{
    int res;

    struct udrv_fb_pkt_write_to_buffer *pkt = (void*)&udrv_pkt->data;
    size_t max_datalen = pktlen
	+ (-sizeof(struct udrv_pkt))
	+ (-sizeof(struct udrv_fb_pkt_write_to_buffer));
    void *data = pkt->data;

    size_t offset = pkt->offset;
    size_t datalen = pkt->datalen;

    if(datalen > max_datalen) {
        fprintf(stderr, "seat_handle_framebuffer_write_to_buffer invalid datalen! (offset=0x%lx, datalen=0x%lx, maxdatalen=0x%lx)\n",
	    (unsigned long)offset,
	    (unsigned long)datalen,
	    (unsigned long)max_datalen
	    );
	datalen = max_datalen;
    }

//    printf("seat_handle_framebuffer_write_to_buffer (offset=0x%lx, datalen=0x%lx)\n",
//	    (unsigned long)offset,
//	    (unsigned long)datalen
//	    );


    res = kfb_framebuffer_copy_direct(
	    seat->backing_fb,
	    offset,
	    data,
	    datalen);
    if(res) {
	fprintf(stderr, "seat_handle_framebuffer_write_to_buffer failed to copy data to framebuffer!\n");
	return res;
    }

    kfb_flush_framebuffer(seat->backing_fb);

    return 0;
}

static const char *progname = "seat";
static inline void
print_usage(void) {
    fprintf(stderr, "%s KBD FB\n",
	    progname);
}
static inline void
panic_usage(void) {
    print_usage();
    exit(-1);
}

int
main(int argc, const char **argv)
{
    if(argc > 0) {
	progname = argv[0];
    }

    const char *kbd_path = NULL;
    const char *fb_path = NULL;
    size_t num_seats = 0;

    {
    int opt;
    while((opt = getopt(argc, (char**)argv, "h")) != -1) {
        switch(opt) {
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

        if(pos_argc < 0) {pos_argc = 0;}

        const char **pos_argv = argv + optind;

        if(pos_argc < 3) {
            panic_usage();
        }

        kbd_path = pos_argv[0];
        fb_path = pos_argv[1];

	num_seats = pos_argc - 2;
	seat_modes = malloc(sizeof(int) * num_seats);
	for(size_t i = 0; i < num_seats; i++) {
	    seat_modes[i] = atoi(pos_argv[i+2]);
	}
    }

    if(kbd_path == NULL) {
	panic_usage();
    }
    if(fb_path == NULL) {
	panic_usage();
    }

    struct kfb_framebuffer *framebuffer = kfb_load_framebuffer(fb_path);
    if(framebuffer == NULL) {
        fprintf(stderr, "Failed to open framebuffer \"%s\"!\n", fb_path);
	return -1;
    }

    struct kbd *kbd = open_kbd(kbd_path);
    if(kbd == NULL) {
	fprintf(stderr, "Failed to open kbd \"%s\"!\n", kbd_path);
	return -1;
    }

    struct seat **seats = malloc(sizeof(struct seat*) * num_seats);
    size_t current_seat = 0;

    for(size_t i = 0; i < num_seats; i++) {
	char *buffer = malloc(64);
	buffer[63] = '\0';

	snprintf(buffer, 64, "seat-%lu", (unsigned long)i);

	struct seat *seat = create_seat(buffer, framebuffer, seat_modes[i], kbd);

	suspend_seat(seat);

	seats[i] = seat;
    }


    int running = 1;

    int lctrl_is_pressed = 0;
    int rctrl_is_pressed = 0;

    resume_seat(seats[current_seat]);

    while(running)
    {
        struct kbd_event event;
        ssize_t amt_read = read(kbd->fd, (void*)&event, sizeof(struct kbd_event));
        size_t num_read = amt_read / sizeof(struct kbd_event);
        if(num_read == 1) {
            // Need to handle a kbd event
            if(event.key == KBD_KEY_LCTRL) {
                lctrl_is_pressed = (event.motion != KBD_MOTION_RELEASED);
            }
            if(event.key == KBD_KEY_RCTRL) {
                rctrl_is_pressed = (event.motion != KBD_MOTION_RELEASED);
            }
            if(lctrl_is_pressed || rctrl_is_pressed) {
                if(event.key == KBD_KEY_TAB && event.motion == KBD_MOTION_PRESSED) {
            	    // cycle the current seat
            	    printf("suspending seat %ld\n", (long)current_seat);
                    suspend_seat(seats[current_seat]);
            	    current_seat++;
            	    if(current_seat >= num_seats) {
            	        current_seat = 0;
            	    }
            	    printf("resuming seat %ld\n", (long)current_seat);
                    resume_seat(seats[current_seat]);
            	    printf("setting seat to %ld\n", (long)current_seat);
                }
            } else {
#define BUFLEN (sizeof(struct udrv_pkt) + sizeof(struct kbd_event))
                char buffer[BUFLEN];
                struct udrv_pkt *pkt = (void*)&buffer;
                pkt->type = UDRV_KBD_PKT_PROVIDE_INPUT;
                pkt->flags = 0;
                *(struct kbd_event *)pkt->data = event;
                write(seats[current_seat]->udrv_kbd, (void*)pkt, BUFLEN);
#undef BUFLEN
	    }
        }

        // Read a packet from the kernel about this framebuffer
#define FB_PKT_BUFLEN FILE_READ_MAX_BUFSIZE
        static char buffer[FB_PKT_BUFLEN];
        ssize_t pktlen = read(seats[current_seat]->udrv_fb, buffer, FB_PKT_BUFLEN);
	if(pktlen > sizeof(struct udrv_pkt)) {
            struct udrv_pkt *udrv_pkt = (void*)&buffer;
            switch(udrv_pkt->type) {
                case UDRV_FB_PKT_SET_MODE:
	    	    seat_handle_framebuffer_set_mode(seats[current_seat], udrv_pkt, pktlen);
	    	    break;
                case UDRV_FB_PKT_WRITE_TO_BUFFER:
	    	    seat_handle_framebuffer_write_to_buffer(seats[current_seat], udrv_pkt, pktlen);
		    break;
                default:
                    fprintf(stderr, "received unrecognized udrv framebuffer packet from the kernel!\n");
		    break;
            }
	}
#undef FB_PKT_BUFLEN
    }

    return 0;
}

