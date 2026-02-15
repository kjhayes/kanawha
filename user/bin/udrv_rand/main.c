
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <kanawha/udrv.h>
#include <kanawha/udrv/rand.h>

int main(int argc, const char **argv)
{
    int fd = open("/sys/udrv/rand/udrv", O_CREAT|O_RDWR, S_IRWXU);
    if(fd < 0) {
	fprintf(stderr, "Failed to create udrv rand device!\n");
	exit(-1);
    }

#define BUFLEN 512

    struct udrv_pkt *pkt = malloc(sizeof(struct udrv_pkt) + BUFLEN);
    if(pkt == NULL) {
	perror("malloc");
	exit(-1);
    }
    memset(pkt, 0, sizeof(struct udrv_pkt) + BUFLEN);

    pkt->type = UDRV_RAND_PKT_PROVIDE_ENTROPY;
    pkt->flags = 0;

    uint8_t initial = (uint8_t)rand();
    size_t iter = 0;

    int running = 1;
    while(running)
    {
	for(size_t i = 0; i < BUFLEN; i++) {
	    int val = rand();
	    if((uint8_t)val == initial) {
		iter++;
		if(iter >= sizeof(int) * 8) {
		    iter = 0;
		    initial = (uint8_t)rand();
		}
	    }
	    pkt->data[i] = (uint8_t)((val >> iter) | (val << ((sizeof(int)*8)-iter)));
	}

	write(fd, (void*)pkt, sizeof(struct udrv_pkt) + BUFLEN);
    }

    close(fd);
    unlink("/sys/udrv/rand/udrv");

    return 0;
}

