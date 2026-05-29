
#include <kanawha/kmalloc.h>
#include <kanawha/printk.h>
#include <kanawha/string.h>
#include <kanawha/vmem.h>

void *
memset(void *str, int c, size_t n)
{

    uint8_t byte = (uint8_t)c;
    uint8_t *dest = str;

    for(size_t i = 0; i < n; i++)
    {
        dest[i] = byte;
    }

    return dest;
}

void *
memcpy(void *dest, const void *src, size_t count)
{
    void *original_dest = dest;
    if(dest == src || count == 0)
    {
        return dest;
    }
    for(size_t i = 0; i < count; i++)
    {
        *(uint8_t *)dest = *(uint8_t *)src;
        dest++;
        src++;
    }
    return original_dest;
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
