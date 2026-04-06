#ifndef __ELK_LIBC_INTERNAL____sFILE_H__
#define __ELK_LIBC_INTERNAL____sFILE_H__

#include <errno.h>
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>
#include <semaphore.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define __ELK_LIBC_INTERNAL__INITIAL_FILE_PREFETCH_BUFLEN (256)

struct __sFILE
{
    fd_t __fd;

    int error;
    unsigned int eof : 1;

    pid_t pfile_pid;

    size_t prefetch_head;
    size_t prefetch_tail;
    size_t prefetch_buflen;
    char *prefetch_buffer;

    sem_t owner_sem;
    pid_t owner_pid;
};

static inline void
__elk_libc_internal__init_sFILE(struct __sFILE *file)
{
    file->prefetch_head = 0;
    file->prefetch_tail = 0;
    file->prefetch_buflen = 0;
    file->prefetch_buffer = NULL;

    file->eof = 0;
    file->error = 0;

    file->pfile_pid = -1;
    sem_init(&file->owner_sem, 0, 1);
    file->owner_pid = -1;
}

static inline void
__elk_libc_internal__deinit_sFILE(struct __sFILE *file)
{
    file->prefetch_head = 0;
    file->prefetch_tail = 0;
    file->prefetch_buflen = 0;
    if(file->prefetch_buffer != NULL)
    {
        free(file->prefetch_buffer);
    }

    file->eof = 0;
    file->error = 0;
}

static inline ssize_t
__elk_libc_internal__file_prefetch_buffered(struct __sFILE *file) {
    if(file->prefetch_head == file->prefetch_tail) {
        // Do some normalization while it is easy...
        file->prefetch_head = 0;
        file->prefetch_tail = 0;
        return 0;
    }
    else if(file->prefetch_tail < file->prefetch_head) {
        return file->prefetch_head - file->prefetch_tail;
    } else {
        size_t amt_end = file->prefetch_buflen - file->prefetch_tail;
        size_t amt_start = file->prefetch_head;
        return amt_end + amt_start;
    }
}

// Read a single character from the file (non-buffered)
static inline int
__elk_libc_internal__file_getc_direct(struct __sFILE *file)
{
    ssize_t res;
    char c;
    res = kanawha_sys_read(file->__fd, &c, sizeof(char));
    switch(res)
    {
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

static inline int
__elk_libc_internal__file_prefetch_buffer_empty(struct __sFILE *file)
{
    return file->prefetch_head == file->prefetch_tail;
}
static inline int
__elk_libc_internal__file_prefetch_buffer_full(struct __sFILE *file)
{
    if(file->prefetch_buflen == 0) {
        // If we have no buffer, then the buffer is "full"
        return 1;
    }
    return ((file->prefetch_head+1)%file->prefetch_buflen) == file->prefetch_tail;
}

static inline int
__elk_libc_internal__file_grow_prefetch_buffer(struct __sFILE *file)
{
    size_t new_len;
    if(file->prefetch_buflen == 0) {
        new_len = __ELK_LIBC_INTERNAL__INITIAL_FILE_PREFETCH_BUFLEN+1;
    } else {
        new_len = ((file->prefetch_buflen-1) * 2)+1;
    }

    char *new_buf = malloc(new_len);
    if(new_buf == NULL) {
        return -ENOMEM;
    }

    size_t amt_buffered = 0;
    if(file->prefetch_tail == file->prefetch_head) {
        // Do nothing
    } else if(file->prefetch_tail < file->prefetch_head) {
        amt_buffered = file->prefetch_head - file->prefetch_tail;
        memcpy(new_buf, file->prefetch_buffer + file->prefetch_tail, amt_buffered);
    } else {
        size_t amt_end = file->prefetch_buflen - file->prefetch_tail;
        size_t amt_start = file->prefetch_head;
        memcpy(new_buf, file->prefetch_buffer + file->prefetch_tail, amt_end);
        memcpy(new_buf+amt_end, file->prefetch_buffer, amt_start);
        amt_buffered = amt_end + amt_start;
    }

    char *old = file->prefetch_buffer;
    file->prefetch_buffer = new_buf;
    file->prefetch_buflen = new_len;
    file->prefetch_tail = 0;
    file->prefetch_head = amt_buffered;
    if(old != NULL) {
        free(old);
    }

    return 0;
}

static inline ssize_t
__elk_libc_internal__file_prefetch_more(struct __sFILE *file, size_t max_more)
{
    int res;

    if(max_more == 0) {
        return -EINVAL;
    }

    if(__elk_libc_internal__file_prefetch_buffer_full(file)) {
        res = __elk_libc_internal__file_grow_prefetch_buffer(file);
        if(res) {
            return res;
        }
    }

    size_t room = 0;
    if(file->prefetch_tail <= file->prefetch_head) {
        room = (file->prefetch_buflen - file->prefetch_head) - (file->prefetch_tail == 0);
    } else {
        room = (file->prefetch_tail - file->prefetch_head) - 1;
    }

    if(room > max_more) {
        room = max_more;
    }

    ssize_t amt_read = kanawha_sys_read(
            file->__fd,
            file->prefetch_buffer + file->prefetch_head,
            room);
    if(amt_read < 0) {
        return amt_read;
    }

    file->prefetch_head += amt_read;

    if(file->prefetch_head >= file->prefetch_buflen) {
        file->prefetch_head = 0;
    }
  
    return amt_read;
}

static inline int
__elk_libc_internal__file_unprefetch(struct __sFILE *file, size_t amt)
{
    ssize_t res;
    size_t amt_buffered = __elk_libc_internal__file_prefetch_buffered(file);
    if(amt > amt_buffered) {
        return -EINVAL;
    }
    res = kanawha_sys_seek(file->__fd, -amt, SEEK_CUR);
    if(res < 0) {
        return res;
    }

    if(file->prefetch_tail <= file->prefetch_head) {
        file->prefetch_head -= amt;
    } else {
        size_t amt_end = file->prefetch_buflen - file->prefetch_tail;
        size_t new_amt_buffered = amt_buffered - amt;

        if(new_amt_buffered >= amt_end) {
            file->prefetch_head -= amt;
        } else {
            file->prefetch_head = file->prefetch_tail + new_amt_buffered;
        }
    }

    if(file->prefetch_head == file->prefetch_tail) {
        file->prefetch_head = 0;
        file->prefetch_tail = 0;
    }

    return 0;
}

// Get a single character from the file (buffered and/or non-buffered)
static inline int
__elk_libc_internal__file_getc(struct __sFILE *file)
{
    ssize_t res;

    if(__elk_libc_internal__file_prefetch_buffer_empty(file)) {
        res = __elk_libc_internal__file_prefetch_more(file, -1UL);
        if(res < 0) {
            return res;
        }
    }

    if(!__elk_libc_internal__file_prefetch_buffer_empty(file))
    {
        char c = file->prefetch_buffer[file->prefetch_tail];
        file->prefetch_tail++;
        file->prefetch_tail = (file->prefetch_tail % file->prefetch_buflen);
        if(file->prefetch_tail == file->prefetch_head) {
            file->prefetch_tail = 0;
            file->prefetch_head = 0;
        }
        return c;
    }
    else
    {
        return __elk_libc_internal__file_getc_direct(file);
    }
}

static inline int
__elk_libc_internal__file_defrag_prefetch_buffer(struct __sFILE *file)
{
    if(file->prefetch_tail == file->prefetch_head) {
        file->prefetch_tail = 0;
        file->prefetch_head = 0;
    }
    else if(file->prefetch_tail < file->prefetch_head) {
        size_t amt = file->prefetch_head - file->prefetch_tail;
        memmove(file->prefetch_buffer,
                file->prefetch_buffer + file->prefetch_tail,
                amt);
        file->prefetch_tail = 0;
        file->prefetch_head = amt;
    } else {
        size_t amt_end = file->prefetch_buflen - file->prefetch_tail;
        void *end_dst = file->prefetch_buffer;
        void *end_src = file->prefetch_buffer + file->prefetch_tail;
        size_t amt_start = file->prefetch_head;
        void *start_dst = file->prefetch_buffer + amt_end;
        void *start_src = file->prefetch_buffer;

        void *smaller_src;
        void *smaller_dst;
        size_t smaller_amt;

        void *larger_src;
        void *larger_dst;
        size_t larger_amt;

        if(amt_end < amt_start) {
            smaller_amt = amt_end;
            smaller_dst = end_dst;
            smaller_src = end_src;
            larger_amt = amt_start;
            larger_dst = start_dst;
            larger_src = start_src;
        } else {
            smaller_amt = amt_start;
            smaller_dst = start_dst;
            smaller_src = start_src;
            larger_amt = amt_end;
            larger_dst = end_dst;
            larger_src = end_src;
        }

        char tmp[smaller_amt];
        memcpy(tmp, smaller_src, smaller_amt);
        memmove(larger_dst, larger_src, larger_amt);
        memcpy(smaller_dst, tmp, smaller_amt);
    }
    return 0;
}

// Push a single character to the read buffer
static inline int
__elk_libc_internal__file_ungetc(char c, struct __sFILE *file)
{
    int res;

    ssize_t off = kanawha_sys_seek(
            file->__fd,
            1,
            SEEK_CUR);
    if(off < 0) {
        return off;
    }

    // Ensure the buffer is long enough
    if(__elk_libc_internal__file_prefetch_buffer_full(file))
    {
        res = __elk_libc_internal__file_grow_prefetch_buffer(file);
        if(res) {
            return res;
        }
    }

    // Insert into the buffer
    file->prefetch_buffer[file->prefetch_head] = c;
    file->prefetch_head = (file->prefetch_head+1)%file->prefetch_buflen;

    return 0;
}

static inline ssize_t
__elk_libc_internal__file_read(struct __sFILE *file,
                               void *restrict dest,
                               size_t size)
{
    ssize_t res;

    if(__elk_libc_internal__file_prefetch_buffer_empty(file) && (size < __ELK_LIBC_INTERNAL__INITIAL_FILE_PREFETCH_BUFLEN))
    {
        res = __elk_libc_internal__file_prefetch_more(file, -1UL);
        if(res < 0) {
            return res;
        }
    }

    if(!__elk_libc_internal__file_prefetch_buffer_empty(file))
    {
        ssize_t copied = 0;
        char *iter = dest;
        while(copied < size && !__elk_libc_internal__file_prefetch_buffer_empty(file)) {
            *iter = file->prefetch_buffer[file->prefetch_tail];
            file->prefetch_tail++;
            if(file->prefetch_tail >= file->prefetch_buflen) {
                file->prefetch_tail = 0;
            }
            copied++;
            iter++;
        }
        res = copied;
    }
    else
    {
        res = kanawha_sys_read(file->__fd, dest, size);
    }

    return res;
}

static inline const char *
__elk_libc_internal__file_peekstr(struct __sFILE *file, size_t min, size_t max)
{
    int res;

    if(min > max)
    {
        // Internal Error!
        return NULL;
    }

    size_t cur_buffered;
    while(1) {
        cur_buffered = __elk_libc_internal__file_prefetch_buffered(file);
        if(cur_buffered >= min && cur_buffered <= max) {
            break;
        }

        if(cur_buffered < min) {
            // We don't have enough data
            ssize_t amt = __elk_libc_internal__file_prefetch_more(file, max - cur_buffered);
            if(amt <= 0) {
                return NULL;
            }
        } else {
            // We have too much data buffered
            res = __elk_libc_internal__file_unprefetch(file, cur_buffered-max);
            if(res) {
                return NULL;
            }
        }
    }

    if(__elk_libc_internal__file_prefetch_buffer_full(file)) {
        res = __elk_libc_internal__file_grow_prefetch_buffer(file);
        if(res) {
            return NULL;
        }
    }

    // Rearrange the prefetch buffer so that it is
    // continuguous and starts at the beginning
    // (normally it is a ring buffer)
    res = __elk_libc_internal__file_defrag_prefetch_buffer(file);
    if(res) {
        return NULL;
    }

    file->prefetch_buffer[file->prefetch_head] = '\0';
    return file->prefetch_buffer;
}

static inline int
__elk_libc_internal__file_purge(struct __sFILE *file)
{
    ssize_t buffered = __elk_libc_internal__file_prefetch_buffered(file);
    if(buffered > 0) {
        ssize_t off = kanawha_sys_seek(
                file->__fd,
                -buffered,
                SEEK_CUR);
        if(off < 0) {
            return -EINVAL;
        }
    }
    free(file->prefetch_buffer);
    file->prefetch_buffer = NULL;
    file->prefetch_buflen = 0;
    file->prefetch_head = 0;
    file->prefetch_tail = 0;
    return 0;
}

// Consume "count" from the file (buffered and/or non-buffered)
static inline int
__elk_libc_internal__file_consume(struct __sFILE *file, size_t count)
{
    ssize_t res;

    res = __elk_libc_internal__file_purge(file);
    if(res) {
        return -EINVAL;
    }

    res = kanawha_sys_seek(
            file->__fd,
            count,
            SEEK_CUR);
    if(res < 0) {
        return res;
    }

    return 0;
}

#endif
