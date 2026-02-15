
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <kanawha/udrv.h>
#include <kanawha/udrv/rand.h>

#define PATHBUFLEN 256

#define UDRV_PATH "/sys/udrv/"

static const char *progname = "mkudrv";
static inline void
panic_usage(void) {
    fprintf(stderr, "%s [TYPE] [NAME]\n",
	    progname);
    exit(-1);
}

int main(int argc, const char **argv)
{
    if(argc > 0) {
	progname = argv[0];
    }
    if(argc != 3) {
	panic_usage();
    }

    const char *udrv_type = argv[1];
    const char *udrv_name = argv[2];

    static char path[PATHBUFLEN];
    snprintf(path, PATHBUFLEN, "%s/%s/%s",
	    UDRV_PATH,
	    udrv_type,
	    udrv_name
	    );
    path[PATHBUFLEN-1] = '\0';

    int fd = open(path, O_CREAT|O_RDWR, S_IRWXU);
    if(fd < 0) {
	fprintf(stderr, "Failed to create udrv device!\n");
	exit(-1);
    }

    close(fd);
    return 0;
}

