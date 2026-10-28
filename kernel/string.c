
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/vmem.h>
#include <kanawha/printer.h>
#include <kanawha/fmt.h>
#include <kanawha/stddef.h>
#include <kanawha/export.h>

static inline void *
memset_bytewise(void *str, int c, size_t n)
{

    uint8_t byte = (uint8_t)c;

    uint8_t *dest = str;
    uint8_t *end = str + n;

    while(dest != end)
    {
        *dest++ = byte;
    }

    return str;
}

void *
memset(void *str, int c, size_t n)
{
    uintptr_t alignmask = sizeof(unsigned long)-1;
    if((n & alignmask) || ((uintptr_t)str & alignmask)) {
        // We are not aligned enough to use unsigned longs
        return memset_bytewise(str, c, n);
    } else {
        unsigned long *strl = str;
        unsigned long *strl_end = (unsigned long*)(str + n);
        unsigned long cl;
        memset_bytewise(&cl, c, sizeof(unsigned long));
        while(strl != strl_end) {
            *strl++ = cl;
        }
        return str;
    }
}

static inline void *
memcpy_bytewise(void *restrict dest, const void *restrict src, size_t count)
{
    void *original_dest = dest;
    if(dest == src || count == 0)
    {
        return dest;
    }
    void *end = dest + count;
    while(dest != end)
    {
        *(uint8_t *)dest++ = *(uint8_t *)src++;
    }
    return original_dest;
}

void *
memcpy(void *restrict dest, const void *restrict src, size_t count)
{
    uintptr_t alignmask = sizeof(unsigned long)-1;
    if((count & alignmask) || ((uintptr_t)dest & alignmask) || ((uintptr_t)src & alignmask))
    {
        // We are not aligned enough to use unsigned longs
        return memcpy_bytewise(dest, src, count);
    } else {
        unsigned long *destl = dest;
        const unsigned long *srcl = src;
        const unsigned long *endl = (unsigned long *)(dest + count);
        while(destl != endl) {
            *destl++ = *srcl++;
        }
        return dest;
    }
}

void *
memmove(void *dest_ptr, const void *src_ptr, size_t count)
{
    /*
     * This isn't strictly standards conforming (stuff like segmentation can
     * mess it up)
     */
    uintptr_t dest = (uintptr_t)dest_ptr;
    uintptr_t src = (uintptr_t)src_ptr;
    uintptr_t dest_end = dest + count;
    uintptr_t src_end = src + count;

    if(dest_end <= src || src_end <= dest)
    {
        // No overlap, we can safely memcpy
        return memcpy(dest_ptr, src_ptr, count);
    }
    if(dest == src || count == 0)
    {
        // Complete overlap, do nothing
        return dest_ptr;
    }

    uint8_t *dest_arr = dest_ptr;
    const uint8_t *src_arr = src_ptr;

    if(dest < src)
    {
        // Copy start to end
        for(size_t i = 0; i < count; i++)
        {
            dest_arr[i] = src_arr[i];
        }
    }
    else
    { // src > dest
        // Copy end to start
        for(size_t i = count - 1; i > 0; i--)
        {
            dest_arr[i] = src_arr[i];
        }
        dest_arr[0] = src_arr[0];
    }

    return dest_ptr;
}

int
memcmp(const void *lhs, const void *rhs, size_t n)
{
    for(size_t i = 0; i < n; i++)
    {
        char l = *(char *)lhs;
        char r = *(char *)rhs;
        if(l != r)
        {
            return l - r;
        }
    }
    return 0;
}

size_t
strlen(const char *str)
{
    DEBUG_ASSERT(KERNEL_ADDR(str));
    const char *term = str;
    while(*term != '\0')
    {
        term++;
        /*
        DEBUG_ASSERT(
                (((uintptr_t)term & ((1ULL<<VMEM_MIN_PAGE_ORDER)-1)) != 0)
                || (vmem_verify_access(
                    (void*)term,
                    1ULL,
                    VMEM_VERIFY_ACCESS_KERNEL|VMEM_VERIFY_ACCESS_READ
                    )));
        */
    }
    return (size_t)(term - str);
}

size_t
strnlen(const char *str, size_t maxlen)
{
    size_t len = 0;
    while(len < maxlen && str[len] != '\0')
    {
        len++;
    }
    return len;
}

char *
strcpy(char *dst, const char *src)
{
    size_t len = strlen(src);
    memcpy(dst, src, len + 1);
    return dst;
}

char *
strncpy(char *dst, const char *src, size_t n)
{
    char *saved_dst = dst;
    for(size_t i = 0; i < n; i++)
    {
        *dst = *src;
        dst++;
        if(*src != '\0')
        {
            src++;
        }
    }
    return saved_dst;
}

int
strcmp(const char *lhs, const char *rhs)
{
    do
    {
        unsigned char diff = (unsigned char)*lhs - (unsigned char)*rhs;
        if(diff != 0)
        {
            return diff;
        }

        if(*lhs == '\0' || *rhs == '\0')
        {
            break;
        }

        lhs++;
        rhs++;
    } while(1);

    return 0;
}

int
strncmp(const char *lhs, const char *rhs, size_t n)
{
    while(n > 0)
    {
        n--;
        unsigned char diff = (unsigned char)*lhs - (unsigned char)*rhs;
        if(diff != 0)
        {
            return diff;
        }

        if(*lhs == '\0' || *rhs == '\0')
        {
            break;
        }

        lhs++;
        rhs++;
    }

    return 0;
}

static char
__to_upper(char c)
{
    if('a' <= c && c <= 'z')
    {
        return c + ('A' - 'a');
    }
    return c;
}

int
strcasecmp(const char *lhs, const char *rhs, size_t n)
{
    do
    {
        unsigned char diff =
            (unsigned char)__to_upper(*lhs) - (unsigned char)__to_upper(*rhs);
        if(diff != 0)
        {
            return diff;
        }

        if(*lhs == '\0' || *rhs == '\0')
        {
            break;
        }

        lhs++;
        rhs++;
    } while(1);

    return 0;
}
int
strncasecmp(const char *lhs, const char *rhs, size_t n)
{
    while(n > 0)
    {
        n--;
        unsigned char diff =
            (unsigned char)__to_upper(*lhs) - (unsigned char)__to_upper(*rhs);
        if(diff != 0)
        {
            return diff;
        }

        if(*lhs == '\0' || *rhs == '\0')
        {
            break;
        }

        lhs++;
        rhs++;
    }

    return 0;
}

char *
kstrdup(const char *str)
{
    size_t len = strlen(str);
    char *clone = kmalloc(len + 1, KM_KERNEL);
    if(clone == NULL)
    {
        return clone;
    }
    memcpy(clone, str, len + 1);
    return clone;
}

// Trying to limit the use of __va and __pa, so these function will
// hopefully help reduce direct use of those functions
void
memcpy_pp(void __phys *dest, void __phys *src, size_t n)
{
    void *dest_v = __va(dest);
    void *src_v = __va(src);
    memcpy(dest_v, src_v, n);
}
void
memcpy_vp(void __phys *dest, void *src, size_t n)
{
    void *dest_v = __va(dest);
    memcpy(dest_v, src, n);
}
void
memcpy_pv(void *dest, void __phys *src, size_t n)
{
    void *src_v = __va(src);
    memcpy(dest, src_v, n);
}
void
memset_p(void __phys *str, int c, size_t n)
{
    void *str_v = __va(str);
    memset(str_v, c, n);
}

// String formatting

struct buffer_printer {
    char *buffer;
    size_t buflen;
    size_t offset;
    struct printer printer;
};

static inline int
buffer_printer_putc(
        struct printer *p,
        char c)
{
    struct buffer_printer *sp =
        container_of(p, struct buffer_printer, printer);
    if(sp->offset < sp->buflen) {
        sp->buffer[sp->offset] = c;
    }
    sp->offset++;
    return 0;
}

static inline void
buffer_printer_init(
        struct buffer_printer *p,
        char *buffer,
        size_t buflen)
{
    p->buffer = buffer;
    p->buflen = buflen;
    p->offset = 0;
    p->printer.write = &printer_write_using_putc;
    p->printer.puts = &printer_puts_using_write;
    p->printer.putc = &buffer_printer_putc;
    return;
}

ssize_t
vsnprintk(
        char *buf,
        size_t size,
        const char *fmt,
        va_list *args)
{
    int res;
    struct buffer_printer sp = {0};
    buffer_printer_init(&sp, buf, size);
    res = fmt_vprint(&sp.printer, fmt, args);
    if(sp.offset < sp.buflen) {
        buf[sp.offset] = '\0';
    } else {
        buf[size-1] = '\0';
    }
    if(res) {
        return res;
    }
    return sp.offset;
}
ssize_t
snprintk(
        char *buf,
        size_t size,
        const char *fmt,
        ...)
{
    ssize_t s;
    va_list args;
    va_start(args, fmt);
    s = vsnprintk(buf, size, fmt, &args);
    va_end(args);
    return s;
}
EXPORT_SYMBOL(snprintk);
EXPORT_SYMBOL(vsnprintk);

struct string_printer {
    unsigned long alloc_flags;
    char *buffer;
    size_t buflen;
    size_t content_len;
    struct printer printer;
};

static inline int
string_printer_putc(
        struct printer *p,
        char c)
{
    struct string_printer *sp =
        container_of(p, struct string_printer, printer);
    if(sp->content_len >= sp->buflen) {
        size_t newlen = sp->buflen * 2;
        if(newlen == 0) {
            newlen = 32;
        }
        char *new_buffer = kzmalloc(newlen, sp->alloc_flags);
        if(new_buffer == NULL) {
            return -ENOMEM;
        }
        memcpy(new_buffer, sp->buffer, sp->content_len);
        char *old_buffer = sp->buffer;
        sp->buffer = new_buffer;
        sp->buflen = newlen;
        if(old_buffer) {
            kfree(old_buffer);
        }
    }
    sp->buffer[sp->content_len] = c;
    sp->content_len++;
    return 0;
}
char *
fmt_kstrdup(
        unsigned long alloc_flags,
        const char *fmt,
        ...)
{
    int res;

    struct string_printer sp = {
        .alloc_flags = alloc_flags,
        .buffer = NULL,
        .buflen = 0,
        .content_len = 0,
        .printer = {
            .putc = string_printer_putc,
            .puts = printer_puts_using_putc,
            .write = printer_write_using_putc,
        },
    };

    va_list args;
    va_start(args, fmt);
    res = fmt_vprint(&sp.printer, fmt, &args);
    if(res) {
        kfree(sp.buffer);
        return NULL;
    }
    va_end(args);

    if(sp.buffer == NULL) {
        return "";
    }
    char *final = kmalloc(sp.content_len + 1, alloc_flags);
    if(final == NULL) {
        kfree(sp.buffer);
        return NULL;
    }
    memcpy(final, sp.buffer, sp.content_len);
    final[sp.content_len] = '\0';
    return final;
}

