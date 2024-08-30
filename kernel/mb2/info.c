
#include <mb2/info.h>

__boot_data struct mb2_info *boot_mb2_info_ptr = NULL;

int mb2_info_for_each_tag(
        struct mb2_info *info,
        mb2_info_tag_handler_f *handler,
        void *private) 
{
    void *tag_ptr = &(info->raw_tags);
    void *end_ptr = tag_ptr + (info->hdr.total_size - sizeof(struct mb2_info));

    while(tag_ptr < end_ptr) {
        if((uintptr_t)tag_ptr & 0b111) {
            // Align back to 8 bytes if we became unaligned
            tag_ptr += 8;
            tag_ptr = (void*)((uintptr_t)tag_ptr & ~0b111);

            // Check to make sure that didn't run us off the end
            if(tag_ptr > end_ptr) {
                break;
            }
        }

        struct mb2_info_tag *tag = (struct mb2_info_tag*)tag_ptr;
        if(tag->hdr.type == 0 && tag->hdr.size == 8) {
            // This is the terminator tag
            break;
        }

        // Call our handler
        (*handler)(info, tag, private);

        // Move on to the next tag
        tag_ptr += tag->hdr.size;
    }

    return 0;
}

