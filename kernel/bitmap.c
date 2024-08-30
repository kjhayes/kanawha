
#include <kanawha/bitmap.h>
#include <kanawha/printk.h>

size_t bitmap_find_first_set(unsigned long *bitmap, size_t num_entries)
{
    size_t num_longs = (num_entries/BITS_PER_LONG) +
                       (num_entries%BITS_PER_LONG != 0);

    size_t bit = num_entries;
    for(size_t long_index = 0; long_index < num_longs; long_index++) {
        unsigned long val = bitmap[long_index];
        if(val == 0) {
            // All zeros
            continue;
        }
        size_t index_in_long = __builtin_ctzl(val);
        bit = (long_index * BITS_PER_LONG) + index_in_long;
        break;
    }
    if(bit >= num_entries) {
      return num_entries;
    }
    return bit;
}

size_t bitmap_find_first_clear(unsigned long *bitmap, size_t num_entries)
{
    size_t num_longs = (num_entries/BITS_PER_LONG) +
                       (num_entries%BITS_PER_LONG != 0);

    size_t bit = num_entries;
    for(size_t long_index = 0; long_index < num_longs; long_index++) {
        unsigned long val = bitmap[long_index];
        if(~val == 0) {
            // All ones
            continue;
        }
        size_t index_in_long = __builtin_ctzl(~val);
        bit = (long_index * BITS_PER_LONG) + index_in_long;
        dprintk("bitmap_find_first_clear: bit=0x%llx, long_index=0x%llx, index_in_long=0x%llx, val=0x%llx, ~val=0x%llx\n",
                (ull_t)bit, (ull_t)long_index, (ull_t)index_in_long, (ull_t)val, (ull_t)~val);
        break;
    }

    if(bit >= num_entries) {
      return num_entries;
    }
    return bit;
}

size_t
bitmap_find_set_range(
        unsigned long *bitmap,
        size_t num_entries,
        size_t num_needed)
{
    size_t num_longs = (num_entries/BITS_PER_LONG) +
                       (num_entries%BITS_PER_LONG != 0);

    size_t current_run = 0;
    size_t current_bit = num_entries;

    size_t bit = num_entries;


    for(size_t long_index = 0; long_index < num_longs; long_index++) {
        unsigned long val = bitmap[long_index];
        
        // This "if" is unnecessary but should speed up large range searches
        if(val == ~0 && ((num_needed - current_run) > BITS_PER_LONG)) {
            if(current_run == 0) {
                current_bit = long_index * BITS_PER_LONG;
            }
            current_run += BITS_PER_LONG;
            continue;
        }

        for(size_t bit_index = 0; bit_index < BITS_PER_LONG; bit_index++) {

            if(current_run >= num_needed) {
                bit = current_bit;
                goto found_region;
            }

            unsigned long shifted = val >> bit_index;
            if(shifted == 0) {
                // All zeros (no point in continuing on this long)
                current_run = 0;
                break;
            }

            if(shifted & 1) {
                if(current_run == 0) {
                    current_bit = long_index * BITS_PER_LONG + bit_index;
                }
                current_run += 1;
            } else {
                current_run = 0;
                continue;
            }
        }
    }

found_region:
    if(bit >= num_entries) {
      return num_entries;
    }
    return bit;
}

size_t
bitmap_find_clear_range(
        unsigned long *bitmap,
        size_t num_entries,
        size_t num_needed)
{
    size_t num_longs = (num_entries/BITS_PER_LONG) +
                       (num_entries%BITS_PER_LONG != 0);


    size_t current_run = 0;
    size_t current_bit = num_entries;

    size_t bit = num_entries;

    for(size_t long_index = 0; long_index < num_longs; long_index++) {
        unsigned long val = bitmap[long_index];

        // This "if" is unnecessary but should speed up large range searches
        if(val == 0 && ((num_needed - current_run) > BITS_PER_LONG)) {
            if(current_run == 0) {
                current_bit = long_index * BITS_PER_LONG;
            }
            current_run += BITS_PER_LONG;
            continue;
        }

        for(size_t bit_index = 0; bit_index < BITS_PER_LONG; bit_index++) {

            if(current_run >= num_needed) {
                bit = current_bit;
                goto found_region;
            }

            long shifted = (long)val >> bit_index; // We want sign extension
            if(shifted == ~0) {
                // All ones (no point in continuing on this long)
                current_run = 0;
                break;
            }

            if((shifted & 1) == 0) {
                if(current_run == 0) {
                    current_bit = long_index * BITS_PER_LONG + bit_index;
                }
                current_run += 1;
            } else {
                current_run = 0;
                continue;
            }
        }
    }

found_region:
    if(bit >= num_entries) {
      return num_entries;
    }
    return bit;
}

