#ifndef __ELK_LIBC_INTERNAL____sFILE_H__
#define __ELK_LIBC_INTERNAL____sFILE_H__

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <semaphore.h>
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>

struct __sFILE
{
    fd_t __fd;

    int error;
    unsigned int eof : 1;

    pid_t pfile_pid;

    size_t peek_datalen;
    size_t peek_buflen;
    char *peek_buffer;

    sem_t owner_sem;
    pid_t owner_pid;
};

static inline void
__elk_libc_internal__init_sFILE(
        struct __sFILE *file)
{
    file->peek_datalen = 0;
    file->peek_buflen = 0;
    file->peek_buffer = NULL;

    file->eof = 0;
    file->error = 0;

    file->pfile_pid = -1;
    sem_init(&file->owner_sem, 0, 1);
    file->owner_pid = -1;
}

static inline void
__elk_libc_internal__deinit_sFILE(
        struct __sFILE *file)
{
    file->peek_datalen = 0;
    file->peek_buflen = 0;
    if(file->peek_buffer != NULL) {
        free(file->peek_buffer);
    }

    file->eof = 0;
    file->error = 0;
}

// Read a single character from the file (non-buffered)
static inline int
__elk_libc_internal__file_getc_direct(
        struct __sFILE *file)
{
    ssize_t res;
    char c;
    while(1) {
        res = kanawha_sys_read(
                file->__fd,
                &c,
                sizeof(char));
	switch(res) {
	    case 1:
		return c;
	    case 0:
		file->eof = 1;
		return EOF;
	    default:
		file->error = 1;
		errno = res;
		return EOF;
	}
    }
}

// Get a single character from the file (buffered and/or non-buffered)
static inline int
__elk_libc_internal__file_getc(
        struct __sFILE *file)
{
    if(file->peek_datalen > 0) {
        char c = file->peek_buffer[0];
        memmove(file->peek_buffer, file->peek_buffer+1, file->peek_datalen-1);
        file->peek_datalen--;
        if(file->peek_datalen == 0) {
            free(file->peek_buffer);
            file->peek_buffer = NULL;
            file->peek_buflen = 0;
        }
        return c;
    } else {
        return __elk_libc_internal__file_getc_direct(file);
    }
}

// Push a single character to the read buffer
static inline int
__elk_libc_internal__file_ungetc(
        char c,
        struct __sFILE *file)
{
    // Ensure the buffer is long enough
    if(file->peek_buflen < file->peek_datalen+1) {
        file->peek_buffer = realloc(file->peek_buffer, file->peek_datalen+1);
        if(file->peek_buffer == NULL) {
            return -ENOMEM;
        }
    }

    // Allocate a spot at the front of the buffer
    if(file->peek_datalen > 0) {
        memmove(file->peek_buffer+1, file->peek_buffer, file->peek_datalen);
    }

    file->peek_datalen += 1;
    file->peek_buffer[0] = c;
    return 0;
}

static inline ssize_t
__elk_libc_internal__file_read(
        struct __sFILE *file,
        void * restrict dest,
        size_t size)
{
    if(file->peek_datalen) {
        if(file->peek_datalen > size) {
            memcpy(dest, file->peek_buffer, size);

            file->peek_datalen -= size;
            memmove(file->peek_buffer,
                    file->peek_buffer+size,
                    file->peek_datalen);

            return size;
        } else {
            // size >= file->peek_datalen
            size_t to_read = file->peek_datalen;
            // Copy our data to the output buffer
            memcpy(dest, file->peek_buffer, to_read);

            // Free the buffer
            file->peek_datalen = 0;
            free(file->peek_buffer);
            file->peek_buffer = NULL;
            file->peek_buflen = 0;

            // Return how many bytes were read
            return to_read;
        }
    } else {
        return kanawha_sys_read(
                file->__fd,
                dest,
                size);
    }

}

static inline const char *
__elk_libc_internal__file_peekstr(
        struct __sFILE *file,
        size_t min,
        size_t max)
{
    if(min > max) {
        // Internal Error!
        return NULL;
    }
    if(max+1 > file->peek_buflen) {
        realloc(file->peek_buffer, max+1);
    }
    while(file->peek_datalen < max) {
        size_t room_left = (file->peek_buflen-1) - file->peek_datalen;
        ssize_t read = kanawha_sys_read(
                file->__fd,
                file->peek_buffer + file->peek_datalen,
                room_left);
        if(read < 0) {
            return NULL;
        }
        else if(read == 0) {
            if(file->peek_datalen >= min) {
                break;
            } else {
                return NULL;
            }
        } else {
            file->peek_datalen += read;
        }
    }
    file->peek_buffer[file->peek_datalen] = '\0';
    return file->peek_buffer;
}

// Consume "count" from the file (buffered and/or non-buffered)
static inline int
__elk_libc_internal__file_consume(
        struct __sFILE *file,
        size_t count)
{
    int res;

    if(file->peek_datalen > count) {
        file->peek_datalen -= count;
        memmove(file->peek_buffer, file->peek_buffer + count, file->peek_datalen);
        return 0;
    } else if(file->peek_datalen <= count) {
        count -= file->peek_datalen;
        file->peek_datalen = 0;
        free(file->peek_buffer);
        file->peek_buffer = NULL;
        file->peek_buflen = 0;
    }

    while(count > 0) {
        res = __elk_libc_internal__file_getc_direct(file);
        if(res) {
            return res;
        }
        count--;
    }

    return 0;
}

static inline int
__elk_libc_internal__file_purge(
        struct __sFILE *file)
{
    free(file->peek_buffer);
    file->peek_buffer = NULL;
    file->peek_buflen = 0;
    file->peek_datalen = 0;
    return 0;
}

#endif
