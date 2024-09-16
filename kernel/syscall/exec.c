
#include <kanawha/syscall.h>
#include <kanawha/file.h>
#include <kanawha/process.h>
#include <kanawha/stdint.h>
#include <kanawha/stddef.h>
#include <kanawha/assert.h>
#include <kanawha/uapi/mmap.h>
#include <kanawha/syscall/mmap.h>
#include <kanawha/fs/node.h>

#include <elf/elf.h>
#include <elf/elf_string.h>

static int
exec_elf64_check_header(
        Elf64_Ehdr *hdr)
{
    if(hdr->e_ident[EI_MAG0] != EI_MAG0_VALID) {
        eprintk("ELF64 File has invalid EI_MAG0!\n");
        return -EINVAL;
    }
    if(hdr->e_ident[EI_MAG1] != EI_MAG1_VALID) {
        eprintk("ELF64 File has invalid EI_MAG1!\n");
        return -EINVAL;
    }
    if(hdr->e_ident[EI_MAG2] != EI_MAG2_VALID) {
        eprintk("ELF64 File has invalid EI_MAG2!\n");
        return -EINVAL;
    }
    if(hdr->e_ident[EI_MAG3] != EI_MAG3_VALID) {
        eprintk("ELF64 File has invalid EI_MAG3!\n");
        return -EINVAL;
    }

    if(hdr->e_ident[EI_CLASS] != ELFCLASS64) {
        eprintk("ELF File is not 64-bit!\n");
        return -EINVAL;
    }

    if(hdr->e_type != ET_EXEC) {
        eprintk("ELF64 File has type = \"%s\"!\n", elf_get_type_string(hdr->e_type));
        return -EINVAL;
    }

    return 0;
}

static int
exec_elf64_load_segment(
        struct process *process,
        fd_t file,
        Elf64_Phdr *phdr)
{
    int res;

    unsigned long prot_flags = 0;
    unsigned long mmap_flags = 0;

    if(phdr->p_memsz == 0) {
        wprintk("exec_elf64_load_segment: PT_LOAD segment with mem_size=0!\n");
        return -EINVAL;
    }

    if(ptr_orderof(phdr->p_offset) < VMEM_MIN_PAGE_ORDER) {
        wprintk("exec_elf64_load_segment: PT_LOAD segment with file_offset=%p not a multiple of the minimum page size!\n",
                (uintptr_t)phdr->p_offset);
        return -EINVAL;
    }

    if(ptr_orderof(phdr->p_vaddr) < VMEM_MIN_PAGE_ORDER) {
        wprintk("exec_elf64_load_segment: PT_LOAD segment with vaddr=%p not a multiple of the minimum page size!\n",
                (uintptr_t)phdr->p_vaddr);
        return -EINVAL;
    }

    size_t memsz = phdr->p_memsz;
    size_t filesz = phdr->p_filesz;
    size_t bsssz = memsz - filesz;

    if(ptr_orderof(filesz) < VMEM_MIN_PAGE_ORDER) {
        wprintk("exec_elf64_load_segment: PT_LOAD segment with file_size=%p not a multiple of the minimum page size!\n",
                (uintptr_t)filesz);
        return -EINVAL;
    }

    if(ptr_orderof(bsssz) < VMEM_MIN_PAGE_ORDER) {
        wprintk("exec_elf64_load_segment: PT_LOAD segment with bss_size=%p not a multiple of the minimum page size!\n",
                (uintptr_t)bsssz);
        return -EINVAL;
    }

    if(phdr->p_flags & PF_R) {
        prot_flags |= MMAP_PROT_READ;
    }
    if(phdr->p_flags & PF_W) {
        prot_flags |= MMAP_PROT_WRITE;
    }
    if(phdr->p_flags & PF_X) {
        prot_flags |= MMAP_PROT_EXEC;
    }

    if(filesz > 0) {
        res = mmap_map_region_exact(
                process,
                file,
                phdr->p_offset,
                phdr->p_vaddr,
                filesz,
                prot_flags,
                mmap_flags | MMAP_PRIVATE);
        if(res) {
            return res;
        }
    } 

    if(bsssz > 0) {
        res = mmap_map_region_exact(
                process,
                NULL_FD,
                0,
                phdr->p_vaddr + filesz,
                bsssz,
                prot_flags,
                mmap_flags | MMAP_ANON);
        if(res) {
            return res;
        }
    }


    return 0;
}

static int
exec_elf64_handle_segment(
        struct process *process,
        fd_t file,
        Elf64_Phdr *phdr)
{
    switch(phdr->p_type) {
        case PT_LOAD:
            return exec_elf64_load_segment(
                    process,
                    file,
                    phdr);
        case PT_NULL:
            return 0;
        default:
            wprintk("Ignoring Unsupported ELF Segment \"%s\" offset=%p, memsz=%p\n",
                    elf_get_phdr_type_string(phdr->p_type), phdr->p_offset, phdr->p_memsz);
            break;
    }



    return 0;
}

static int
process_exec_elf64(
        struct process *process,
        fd_t file,
        struct file *desc)
{
    int res;

    if((desc->access_flags & FILE_PERM_READ) == 0) {
        eprintk("process_exec_elf64: file does not have READ permissions!\n");
        return -EPERM;
    }

    struct fs_node *elf_node = desc->path->fs_node;

    Elf64_Ehdr elf_hdr;
    size_t amount = sizeof(Elf64_Ehdr);

    res = fs_node_paged_read(elf_node, 0, &elf_hdr, amount);
    if(res) {
        return res;
    }

    res = exec_elf64_check_header(&elf_hdr);
    if(res) {
        return res;
    }

    DEBUG_ASSERT(sizeof(Elf64_Phdr) == elf_hdr.e_phentsize);

    Elf64_Phdr phdr;
    for(size_t i = 0; i < elf_hdr.e_phnum; i++)
    {
        amount = elf_hdr.e_phentsize;
        res = fs_node_paged_read(elf_node, elf_hdr.e_phoff + (i * elf_hdr.e_phentsize), &phdr, amount);
        if(res) {
            return res;
        }

        if(amount != elf_hdr.e_phentsize) {
            return -EINVAL;
        }

        res = exec_elf64_handle_segment(process, file, &phdr);

        if(res) {
            return res;
        }
    }

    process_clear_forced_ip(process);
    res = process_force_ip(process, (void __user*)elf_hdr.e_entry);
    if(res) {
        return res;
    }

    return 0;
}

int
syscall_exec(
        struct process *process,
        fd_t file,
        unsigned long exec_flags)
{
    int res;

    struct file *desc =
        file_table_get_file(process->file_table, process, file);

    if(desc == NULL) {
        file_table_put_file(process->file_table, process, desc);
        return -EINVAL;
    }

    if((desc->access_flags & FILE_PERM_EXEC) == 0) {
        file_table_put_file(process->file_table, process, desc);
        eprintk("syscall_exec: file does not have EXEC permissions!\n");
        return -EPERM;
    }

    res = mmap_deattach(process->mmap, process);
    if(res) {
        file_table_put_file(process->file_table, process, desc);
        eprintk("syscall_exec: Failed to deattach mmap! (err=%s)\n",
                errnostr(res));
        return res;
    }

    res = mmap_create(PROCESS_LOWMEM_SIZE, process);
    if(res) {
        file_table_put_file(process->file_table, process, desc);
        eprintk("syscall_exec: Failed to create new mmap! (err=%s)\n",
                errnostr(res));
        return res;
    }

    res = process_exec_elf64(process, file, desc);
    if(res) {
        file_table_put_file(process->file_table, process, desc);
        return res;
    }

    dprintk("syscall_exec: desc->path->fs_node->index = %lld\n", (sll_t)desc->path->fs_node->cache_node.key);
    file_table_put_file(process->file_table, process, desc);

    res = vmem_flush_region(process->mmap->vmem_region);
    if(res) {
        eprintk("syscall_exec: Failed to flush mmap region!\n");
        return res;
    }

    return 0;
}


