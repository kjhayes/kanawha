
#include <kanawha/syscall.h>
#include <kanawha/proc/process.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/irq.h>
#include <kanawha/stdint.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/ptree.h>
#include <kanawha/vmem.h>
#include <kanawha/stddef.h>
#include <kanawha/assert.h>
#include <kanawha/proc/process.h>
#include <kanawha/page_alloc.h>
#include <kanawha/proc/mmap.h>
#include <kanawha/vmem.h>
#include <kanawha/fs/node.h>

int
syscall_mmap(
        struct process *process,
        fd_t file,
        size_t file_offset,
        void __user * __user* where,
        size_t size,
        unsigned long mmap_flags)
{
    int res;

    void __user *requested;
    res = process_read_usermem(
            process,
            &requested,
            where,
            sizeof(void __user *));
    if(res) {
        wprintk("syscall_mmap: Failed to read requested address at %p from usermem (err=%s)\n",
                where, errnostr(res));
        return res;
    }

    uint8_t type = mmap_flags & 0b11;

    // Mis-aligned/Mis-sized

    if(type != MMAP_ANON && (ptr_orderof(file_offset) < VMEM_MIN_PAGE_ORDER)) {
        wprintk("syscall_mmap: file_offset is not aligned to the minimum vmem page size!\n");
        return -EINVAL;
    }
    if(ptr_orderof(size) < VMEM_MIN_PAGE_ORDER) {
        wprintk("syscall_mmap: size is not a multiple of the minimum vmem page size!\n");
        return -EINVAL;
    }

    if(mmap_flags & MMAP_EXACT)
    {
        if(ptr_orderof(requested) < VMEM_MIN_PAGE_ORDER) {
            wprintk("syscall_mmap: virtual address is not aligned to the minimum vmem page size!\n");
            return -EINVAL;
        }
        res = mmap_map_region_exact(
                process,
                file,
                file_offset,
                (uintptr_t)requested,
                size,
                mmap_flags);
        if(res) {
            wprintk("syscall_mmap: mmap_map_region_exact returned %s\n",
                    errnostr(res));
            return res;
        }
    }
    else
    { // The kernel can adjust the offset
        uintptr_t hint_offset = (uintptr_t)requested;
        res = mmap_map_region(
                process,
                file,
                file_offset,
                &hint_offset,
                size,
                mmap_flags);
        if(res) {
            wprintk("syscall_mmap: mmap_map_region returned %s\n",
                    errnostr(res));
            return res;
        }

        // If the kernel modified the address,
        // we need to write the actual region base
        // back to usermem
        if(hint_offset != (uintptr_t)requested) {
            requested = (void __user *)hint_offset;
            res = process_write_usermem(
                    process,
                    where,
                    &requested,
                    sizeof(void __user *));
            if(res) {
                // TODO: this is tricky, it's not really possible to
                // undo the mapping at this point (especially once
                // we allow over-writing other mappings)
                wprintk("syscall_mmap: Successfully mapped region, but failed to write address back to user memory! (err=%s)\n",
                        errnostr(res));
                return res;
            }
        }
    }

    res = vmem_flush_region(process->mmap->vmem_region);
    if(res) {
        eprintk("syscall_mmap: Failed to flush mmap region!\n");
        return res;
    }
    

    return 0;
}

int
syscall_munmap(
        struct process *process,
        void __user *mapping) 
{
    int res;
    struct mmap *mmap = process->mmap;
    DEBUG_ASSERT(KERNEL_ADDR(mmap));
    DEBUG_ASSERT(KERNEL_ADDR(process));
    if((uintptr_t)mapping >= mmap->vmem_region->size) 
    {
        wprintk("syscall_munmap: mapping at (%p) would be outside of user-memory!\n");
        return -EINVAL;
    }

    res = mmap_unmap_region(
            process,
            (uintptr_t)mapping);
    if(res) {
        wprintk("syscall_munmap: mmap_unmap_region returned %s\n",
                errnostr(res));
        return res;
    }

    return 0;
}

