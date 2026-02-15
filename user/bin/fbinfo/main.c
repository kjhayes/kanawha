
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kfb/kfb.h"

static const char *progname = "fbinfo";

int main(int argc, const char **argv)
{
    if(argc > 0) {
        progname = argv[0];
    }
    if(argc != 2) {
        fprintf(stderr, "Usage: %s [FB-PATH]\n",
                progname);
        exit(EXIT_FAILURE);
    }

    const char *fb_path = argv[1];
    struct kfb_framebuffer *fb = kfb_load_framebuffer(fb_path);
    if(fb == NULL) {
        fprintf(stderr, "Failed to load framebuffer \"%s\"!\n",
                fb_path);
        exit(EXIT_FAILURE);
    }

    size_t mode = 0;
    while(1) {

        struct fb_mode_info *info = kfb_load_mode_info(fb, mode);
        if(info == NULL) {
            break;
        }

        printf("MODE[%ld] layer_count=%ld\n",
                mode,
                info->layer_count);
        for(size_t i = 0; i < info->layer_count; i++) {
            struct fb_layer_info *layer = &info->layer_infos[i];
            printf("\tLayer[%ld] {\n", i);
            printf("\t\torder=0x%x\n", layer->layout.order);
            printf("\t\tformat=0x%x\n",layer->layout.format);
            printf("\t\twidth=%lu\n",  layer->layout.width);
            printf("\t\theight=%lu\n", layer->layout.height);
            printf("\t\toffset=%lu\n", layer->layout.offset);
            printf("\t\tstride=%lu\n", layer->layout.stride);
            printf("\t}\n");
        }

        kfb_unload_mode_info(fb, info);

        mode++;
    }

    return 0;
}

