#ifndef __KANAWHA__ELK_SYSCALL_H__
#define __KANAWHA__ELK_SYSCALL_H__

#define CONFIG_X64

#include <kanawha/uapi/file.h>
#include <kanawha/uapi/stdint.h>

__attribute__((noreturn))
void exit(int exitcode);

fd_t open(
        fd_t parent,
        const char *name,
        unsigned long access_flags,
        unsigned long mode_flags);

int close(
        fd_t file);

int read(
        fd_t file,
        void *dest,
        size_t src_offset,
        size_t size);

int write(
        fd_t file,
        size_t dest_offset,
        void *src,
        size_t size);

int mmap(
        fd_t file,
        size_t file_offset,
        void *where,
        size_t size,
        unsigned long prot_flags,
        unsigned long mmap_flags);

int munmap(
        void *mapping);

int exec(
        fd_t file,
        unsigned long exec_flags);

int environ(
        const char *key,
        char *value,
        size_t len,
        int opcode);

#endif
