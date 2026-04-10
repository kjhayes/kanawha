
#include <kanawha/assert.h>
#include <kanawha/exec_type.h>
#include <kanawha/fs/node.h>
#include <kanawha/kmalloc.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/proc/mmap.h>
#include <kanawha/proc/process.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/types.h>
#include <kanawha/uapi/mmap.h>

#include <elf/elf.h>
#include <elf/elf_string.h>

__attribute__((weak)) int
arch_exec_elf64_setup_tls(struct process *process, void __user *tls_base)
{
    eprintk("Cannot handle PT_TLS segment on current architecture -EUNIMPL!\n");
    return -EUNIMPL;
}

static int
exec_elf64_check_header(Elf64_Ehdr *hdr)
{
    if(hdr->e_ident[EI_MAG0] != EI_MAG0_VALID)
    {
        eprintk("ELF64 File has invalid EI_MAG0!\n");
        return -EINVAL;
    }
    if(hdr->e_ident[EI_MAG1] != EI_MAG1_VALID)
    {
        eprintk("ELF64 File has invalid EI_MAG1!\n");
        return -EINVAL;
    }
    if(hdr->e_ident[EI_MAG2] != EI_MAG2_VALID)
    {
        eprintk("ELF64 File has invalid EI_MAG2!\n");
        return -EINVAL;
    }
    if(hdr->e_ident[EI_MAG3] != EI_MAG3_VALID)
    {
        eprintk("ELF64 File has invalid EI_MAG3!\n");
        return -EINVAL;
    }

    if(hdr->e_ident[EI_CLASS] != ELFCLASS64)
    {
        eprintk("ELF File is not 64-bit!\n");
        return -EINVAL;
    }

    if(hdr->e_type != ET_EXEC)
    {
        eprintk("ELF64 File has type = \"%s\"!\n",
                elf_get_type_string(hdr->e_type));
        return -EINVAL;
    }

    return 0;
}

static int
exec_elf64_handle_load_segment(struct process *process,
                               fd_t file,
                               Elf64_Phdr *phdr)
{
    int res;

    unsigned long mmap_flags = 0;

    if(phdr->p_memsz == 0)
    {
        wprintk("exec_elf64_load_segment: %s segment with mem_size=0!\n",
                elf_get_phdr_type_string(phdr->p_type));
        return -EINVAL;
    }

    uintptr_t offset = phdr->p_offset;
    uintptr_t vaddr = phdr->p_vaddr;
    size_t memsz = phdr->p_memsz;
    size_t filesz = phdr->p_filesz;

    if((offset & ((1ULL << VMEM_MIN_PAGE_ORDER) - 1)) !=
       (vaddr & ((1ULL << VMEM_MIN_PAGE_ORDER) - 1)))
    {
        wprintk("exec_elf64_load_segment: %s segment with file_offset=%p, "
                "vaddr=%p with different page offsets!\n",
                elf_get_phdr_type_string(phdr->p_type),
                (uintptr_t)offset,
                (uintptr_t)vaddr);
        return -EINVAL;
    }

    if(ptr_orderof(vaddr) < VMEM_MIN_PAGE_ORDER)
    {
        // Need to align both the file_offset and vaddr down to the nearest
        // page
        size_t page_offset = (vaddr & ((1ULL << VMEM_MIN_PAGE_ORDER) - 1));
        vaddr -= page_offset;
        offset -= page_offset;

        // Increase the file size to compensate
        filesz += page_offset;
    }

    if(ptr_orderof(filesz) < VMEM_MIN_PAGE_ORDER)
    {
        dprintk("exec_elf64_handle_load_segment: %s segment with file_size=%p "
                "not a multiple of the minimum page size: rounding up\n",
                elf_get_phdr_type_string(phdr->p_type),
                (uintptr_t)filesz);
        filesz += ((1ULL << VMEM_MIN_PAGE_ORDER) - 1);
        filesz &= ~((1ULL << VMEM_MIN_PAGE_ORDER) - 1);
    }

    size_t bsssz = 0;
    if(memsz > filesz)
    {
        bsssz = memsz - filesz;
    }

    if(ptr_orderof(bsssz) < VMEM_MIN_PAGE_ORDER)
    {
        dprintk("exec_elf64_handle_load_segment: %s segment with bss_size=%p "
                "not a multiple of the minimum page size: rounding up\n",
                elf_get_phdr_type_string(phdr->p_type),
                (uintptr_t)bsssz);
        bsssz += ((1ULL << VMEM_MIN_PAGE_ORDER) - 1);
        bsssz &= ~((1ULL << VMEM_MIN_PAGE_ORDER) - 1);
    }

    if(phdr->p_flags & PF_R)
    {
        mmap_flags |= MMAP_PROT_READ;
    }
    if(phdr->p_flags & PF_W)
    {
        mmap_flags |= MMAP_PROT_WRITE;
    }
    if(phdr->p_flags & PF_X)
    {
        mmap_flags |= MMAP_PROT_EXEC;
    }

    if(filesz > 0)
    {
        res = mmap_map_region_exact(
            process,
            file,
            offset,
            vaddr,
            filesz,
            mmap_flags |
                (mmap_flags & MMAP_PROT_WRITE ? MMAP_PRIVATE : MMAP_SHARED));
        if(res)
        {
            return res;
        }
    }

    if(bsssz > 0)
    {
        res = mmap_map_region_exact(process,
                                    0,
                                    0,
                                    vaddr + filesz,
                                    bsssz,
                                    mmap_flags | MMAP_ANON);
        if(res)
        {
            return res;
        }
    }

    return 0;
}

static int
exec_elf64_handle_tls_segment(struct process *process,
                              fd_t file,
                              Elf64_Phdr *phdr)
{
    int res;

    unsigned long mmap_flags = 0;

    if(phdr->p_memsz == 0)
    {
        wprintk("exec_elf64_handle_tls_segment: %s segment with mem_size=0!\n",
                elf_get_phdr_type_string(phdr->p_type));
        return -EINVAL;
    }

    uintptr_t offset = phdr->p_offset;
    uintptr_t vaddr = phdr->p_vaddr;
    size_t memsz = phdr->p_memsz;
    size_t filesz = phdr->p_filesz;

    if((offset & ((1ULL << VMEM_MIN_PAGE_ORDER) - 1)) !=
       (vaddr & ((1ULL << VMEM_MIN_PAGE_ORDER) - 1)))
    {
        wprintk("exec_elf64_handle_load_segment: %s segment with "
                "file_offset=%p, vaddr=%p with different page offsets!\n",
                elf_get_phdr_type_string(phdr->p_type),
                (uintptr_t)offset,
                (uintptr_t)vaddr);
        return -EINVAL;
    }

    if(ptr_orderof(vaddr) < VMEM_MIN_PAGE_ORDER)
    {
        // Need to align both the file_offset and vaddr down to the nearest
        // page
        size_t page_offset = (vaddr & ((1ULL << VMEM_MIN_PAGE_ORDER) - 1));
        vaddr -= page_offset;
        offset -= page_offset;

        // Increase the file size to compensate
        filesz += page_offset;
    }

    if(ptr_orderof(filesz) < VMEM_MIN_PAGE_ORDER)
    {
        dprintk("exec_elf64_handle_tls_segment: %s segment with file_size=%p "
                "not a multiple of the minimum page size: rounding up\n",
                elf_get_phdr_type_string(phdr->p_type),
                (uintptr_t)filesz);
        filesz += ((1ULL << VMEM_MIN_PAGE_ORDER) - 1);
        filesz &= ~((1ULL << VMEM_MIN_PAGE_ORDER) - 1);
    }

    size_t bsssz = 0;
    if(memsz > filesz)
    {
        bsssz = memsz - filesz;
    }

    if(ptr_orderof(bsssz) < VMEM_MIN_PAGE_ORDER)
    {
        dprintk("exec_elf64_handle_tls_segment: %s segment with bss_size=%p "
                "not a multiple of the minimum page size: rounding up\n",
                elf_get_phdr_type_string(phdr->p_type),
                (uintptr_t)bsssz);
        bsssz += ((1ULL << VMEM_MIN_PAGE_ORDER) - 1);
        bsssz &= ~((1ULL << VMEM_MIN_PAGE_ORDER) - 1);
    }

    if(phdr->p_flags & PF_R)
    {
        mmap_flags |= MMAP_PROT_READ;
    }
    if(phdr->p_flags & PF_W)
    {
        mmap_flags |= MMAP_PROT_WRITE;
    }
    if(phdr->p_flags & PF_X)
    {
        mmap_flags |= MMAP_PROT_EXEC;
    }

    res = mmap_find_free_region(process, &vaddr, filesz + bsssz);
    if(res)
    {
        return res;
    }

    if(filesz > 0)
    {
        res = mmap_map_region_exact(
            process,
            file,
            offset,
            vaddr,
            filesz,
            mmap_flags |
                (mmap_flags & MMAP_PROT_WRITE ? MMAP_PRIVATE : MMAP_SHARED));
        if(res)
        {
            return res;
        }
    }

    if(bsssz > 0)
    {
        res = mmap_map_region_exact(process,
                                    0,
                                    0,
                                    vaddr + filesz,
                                    bsssz,
                                    mmap_flags | MMAP_ANON);
        if(res)
        {
            return res;
        }
    }

    res = arch_exec_elf64_setup_tls(process, (void __user *)vaddr);
    if(res)
    {
        return res;
    }

    return 0;
}
static int
exec_elf64_handle_segment(struct process *process, fd_t file, Elf64_Phdr *phdr)
{
    switch(phdr->p_type)
    {
    case PT_LOAD:
        return exec_elf64_handle_load_segment(process, file, phdr);
    case PT_TLS:
        return exec_elf64_handle_tls_segment(process, file, phdr);
    case PT_NULL:
        return 0;
    case PT_GNU_STACK:
        // This is just a note requesting
        // that the stack is not executable,
        // we don't map a stack for userspace
        // so we can ignore it.
        return 0;
    default:
        printk("Ignoring Unsupported ELF Segment \"%s\" (0x%lx) offset=%p, "
               "memsz=%p\n",
               elf_get_phdr_type_string(phdr->p_type),
               (ul_t)phdr->p_type,
               phdr->p_offset,
               phdr->p_memsz);
        break;
    }

    return 0;
}

static int
process_exec_elf64(struct process *process, fd_t file, struct file *desc)
{
    int res;

    if((desc->access_flags & FILE_PERM_READ) == 0)
    {
        eprintk("process_exec_elf64: file does not have READ permissions!\n");
        return -EPERM;
    }

    struct fs_node *elf_node = fs_path_get_fs_node(desc->path);
    if(elf_node == NULL)
    {
        return -EINVAL;
    }

    Elf64_Ehdr elf_hdr;
    size_t amount = sizeof(Elf64_Ehdr);

    res = fs_node_paged_read(elf_node, 0, &elf_hdr, amount, 0);
    if(res)
    {
        return res;
    }

    DEBUG_ASSERT(sizeof(Elf64_Phdr) == elf_hdr.e_phentsize);

    Elf64_Phdr phdr;
    for(size_t i = 0; i < elf_hdr.e_phnum; i++)
    {
        amount = elf_hdr.e_phentsize;
        res = fs_node_paged_read(elf_node,
                                 elf_hdr.e_phoff + (i * elf_hdr.e_phentsize),
                                 &phdr,
                                 amount,
                                 0);
        if(res)
        {
            return res;
        }

        if(amount != elf_hdr.e_phentsize)
        {
            return -EINVAL;
        }

        res = exec_elf64_handle_segment(process, file, &phdr);

        if(res)
        {
            return res;
        }
    }

    process->user_ip = (void __user *)elf_hdr.e_entry;

    return 0;
}

static int
elf64_exec_type_probe(struct exec_type *exec_type,
                      struct process *process,
                      struct file *desc)
{
    int res;
    struct fs_node *elf_node = fs_path_get_fs_node(desc->path);
    if(elf_node == NULL)
    {
        return EXEC_TYPE_PROBE_REJECT;
    }

    Elf64_Ehdr elf_hdr;
    size_t amount = sizeof(Elf64_Ehdr);

    res = fs_node_paged_read(elf_node, 0, &elf_hdr, amount, 0);
    if(res)
    {
        return EXEC_TYPE_PROBE_REJECT;
    }

    res = exec_elf64_check_header(&elf_hdr);
    if(res)
    {
        return EXEC_TYPE_PROBE_REJECT;
    }

    return EXEC_TYPE_PROBE_CLAIM;
}

static int
elf64_exec_type_load(struct exec_type *exec_type,
                     struct process *process,
                     struct file *file)
{
    return process_exec_elf64(process, file->table_node.key, file);
}

static struct exec_type_ops elf64_exec_type_ops = {
    .probe = elf64_exec_type_probe,
    .load = elf64_exec_type_load,
};
static struct exec_type elf64_exec_type = {
    .ops = &elf64_exec_type_ops,
};

static int
register_elf64_exec_type(void)
{
    return register_exec_type(&elf64_exec_type, "elf64");
}
declare_init_desc(late,
                  register_elf64_exec_type,
                  "Registering ELF64 Executable Format");
