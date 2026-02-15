
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <kanawha/udrv.h>
#include <kanawha/udrv/term.h>
#include <getopt.h>

static const char *progname = "udrv_term";
static inline void
panic_usage(void) {
    fprintf(stderr, "%s UDRV_TERM [-i (send stdin as input to device)] [-o (read from device to stdout)]\n",
	    progname);
    exit(-1);
}

int main(int argc, const char **argv)
{
    if(argc > 0) {
	progname = argv[0];
    }

    const char *path = NULL;
    int input = 0;
    int output = 0;

    {
    int opt;
    while((opt = getopt(argc, (char**)argv, "io")) != -1) {
        switch(opt) {
            // Handle Any Short Options
            case 'i':
                input = 1;
                break;
            case 'o':
                output = 1;
                break;
            default:
                panic_usage();
        }
    }
    }

    if(input && output) {
	fprintf(stderr, "Only one of -i -o can be selected!\n");
	panic_usage();
    }
    if(!input && !output) {
	fprintf(stderr, "One of -i -o must be selected!\n");
	panic_usage();
    }

    {
        int pos_argc = argc - optind;

        if(pos_argc < 0) {pos_argc = 0;}

        const char **pos_argv = argv + optind;

        if(pos_argc != 1) {
            panic_usage();
        }

        path = pos_argv[0];
    }

    if(path == NULL) {
	panic_usage();
    }
    int fd = open(path, O_RDWR);
    if(fd < 0) {
	fprintf(stderr, "Failed to open udrv terminal device!\n");
	exit(-1);
    }

#define BUFLEN 0x1000
    static char buffer[BUFLEN];

    int running = 1;
    if(input) {
	// Take input from stdin and send it to the device
	while(running) {
	    char c = getchar();
	    struct udrv_pkt *pkt = (void*)buffer;
	    pkt->type = UDRV_TERM_PKT_PROVIDE_INPUT;
	    pkt->flags = 0;
	    pkt->data[0] = c;
	    ssize_t written = write(fd, buffer, sizeof(*pkt) + 1);
	    if(written <= 0) {
		break;
	    }
	}
    } else if(output) {
	// Read from the device and send it to stdout
	while(running) {
	    ssize_t amt = read(fd, buffer, BUFLEN);
	    if(amt > sizeof(struct udrv_pkt)) {
		struct udrv_pkt *recv = (void*)buffer;
		size_t datalen = amt - sizeof(*recv);
		//printf("datalen=%ld\n", (long)datalen);
		switch(recv->type) {
		    case UDRV_TERM_PKT_PUTCHARS:
			{
			for(size_t i = 0; i < datalen; i++) {
			    char c = recv->data[i];
			    putchar(c);
			}
			break;
			}
		    default:
			break; // Ignore unknown packet
		}
	    }
	    if(amt <= 0) {
		break;
	    }
	}
    }

    close(fd);
    return 0;
}

