
#include "kfb/kfb.h"
#include "term.h"

int
render_text_layer(struct kfb_framebuffer *fb,
                  int layer,
                  struct fb_mode_info *mode_info)
{
    struct fb_layer_info *layer_info = &mode_info->layer_infos[layer];
    while(running)
    {
        for(size_t y = 0; y < TERM_HEIGHT; y++)
        {
            if(y > layer_info->height)
            {
                break;
            }
            for(size_t x = 0; x < TERM_WIDTH; x++)
            {
                char c = terminal_data.character_buffer[x + (y * TERM_WIDTH)];
                if(x > layer_info->width)
                {
                    break;
                }
                fb->buffer_data[layer_info->offset + (x * layer_info->stride) +
                                ((y * layer_info->stride) *
                                 layer_info->width)] = c;
            }
        }
        kfb_flush_framebuffer(fb);
    }
    return 0;
}
