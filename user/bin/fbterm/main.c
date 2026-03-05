
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <kanawha/file.h>
#include <kanawha/spawn.h>
#include <kanawha/sys-wrappers.h>
#include <kfb/kfb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ansi.h"
#include "color.h"
#include "font.h"
#include "render.h"
#include "term.h"

static const char *prog_name = "fbterm";

static inline void
find_maximum_fb_mode(struct kfb_framebuffer *fb,
                     int *best_mode_out,
                     int *best_layer_out)
{
    int best_mode = -EINVAL;
    int best_layer = -EINVAL;
    size_t best_dimensions = 0;
    int mode = 0;

    while(1)
    {
        struct fb_mode_info *info = kfb_load_mode_info(fb, mode);
        if(info == NULL)
        {
            break;
        }

        for(int layer = 0; layer < info->layer_count; layer++)
        {
            struct fb_layer_info *layer_info = &info->layer_infos[layer];
            size_t dimensions;
            switch(layer_info->layout.format)
            {
            case GFX_FORMAT_ASCII:
            case GFX_FORMAT_VGA_CHAR:
                dimensions = 0;
                break;
            default:
                dimensions =
                    layer_info->layout.width * layer_info->layout.height;
                break;
            }

            if(dimensions > best_dimensions)
            {
                best_mode = mode;
                best_layer = layer;
                break;
            }
        }

        kfb_unload_mode_info(fb, info);
        mode++;
    }

    *best_mode_out = best_mode;
    *best_layer_out = best_layer;
}

static inline void
panic_usage(void)
{
    fprintf(stderr,
            "Usage: %s [-f framebuffer] [-t psf1-font] [-m mode] [-l layer] "
            "[-d log_file]\n",
            prog_name);
    exit(EXIT_FAILURE);
}

int
main(int argc, const char **argv)
{
    int res;

    if(argc > 0)
    {
        prog_name = argv[0];
    }

    FILE *log_file = NULL;
    const char *log_file_path = NULL;

    const char *font_path = NULL;
    const char *fb_path = NULL;
    int mode = 0;
    int layer = 0;

    int opt;
    while((opt = getopt(argc, (char **)argv, "f:t:m:l:d:")) != -1)
    {
        switch(opt)
        {
        case 'f':
            fb_path = optarg;
            break;
        case 'd':
            log_file_path = optarg;
            break;
        case 't':
            font_path = optarg;
            break;
        case 'm':
            mode = atoi(optarg);
            break;
        case 'l':
            layer = atoi(optarg);
            break;
        default:
            panic_usage();
        }
    }

    if(font_path == NULL || fb_path == NULL)
    {
        panic_usage();
    }

    if(log_file_path != NULL)
    {
        log_file = fopen(log_file_path, "w");
    }

    struct font_data *fdata = load_font(font_path);
    if(fdata == NULL)
    {
        fprintf(stderr, "Failed to load font \"%s\"!\n", font_path);
        exit(EXIT_FAILURE);
    }

    struct kfb_framebuffer *fb = kfb_load_framebuffer(fb_path);
    if(fb == NULL)
    {
        fprintf(stderr, "Failed to open framebuffer: \"%s\"!\n", fb_path);
        exit(EXIT_FAILURE);
    }

    res = kfb_set_current_mode(fb, mode);
    if(res)
    {
        fprintf(stderr, "Failed to set framebuffer mode to %d!\n", mode);
        exit(EXIT_FAILURE);
    }

#define TERM_WIDTH 80
#define TERM_HEIGHT 50

    res = init_terminal(stdin, log_file, TERM_WIDTH, TERM_HEIGHT, mode);
    if(res)
    {
        fprintf(stderr, "Failed to allocate terminal buffer!\n");
        exit(EXIT_FAILURE);
    }

    res = ansi_terminal_init(&terminal_data);
    if(res)
    {
        fprintf(stderr, "Failed to init ansi terminal!\n");
        exit(EXIT_FAILURE);
    }

    while(terminal_data.running)
    {
        render_update(&terminal_data, fdata, fb, layer);

        ansi_terminal_update(&terminal_data);
        for(size_t __i = 0; __i < 256; __i++)
        {
            struct pollfd pollfd[1];
            pollfd[0].fd = fileno(terminal_data.input_file);
            pollfd[0].events = POLLIN | POLLPRI;
            res = poll(pollfd, 1, 0);
            if(res > 0 && (pollfd[0].revents & (POLLIN | POLLPRI)))
            {
                // Only update the terminal if we know we can read
                // at least 1 character
                ansi_terminal_update(&terminal_data);
            }
            else
            {
                break;
            }
        }
    }

    deinit_terminal();
    unload_font(fdata);
    kfb_unload_framebuffer(fb);

    return 0;
}
