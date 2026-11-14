
#include <arch/x64/rar.h>
#include <kanawha/attribute.h>

struct __packed x64_rar_raw_page_inval {
    uint8_t subtype : 3;
    uint8_t stride : 2;
    uint8_t num_pages : 6;
    uint64_t __mbz_0 : 64;
    uint64_t __mbz_1 : 21;
    uint64_t cr3;
    uint64_t linear_addr;
};
_Static_assert(
        sizeof(struct x64_rar_raw_page_inval) == 28,
        "x64 RAR Page Invalidation Payload is not exactly 28 bytes!"
        );

struct __packed x64_rar_raw_pcid_inval {
    uint8_t subtype : 3;
    uint8_t stride : 2;
    uint8_t num_pages : 6;
    uint64_t __mbz_0 : 64;
    uint64_t __mbz_1 : 21;
    uint32_t pcid : 32;
    uint32_t __ign0 : 32;
    uint64_t linear_addr : 64;
};
_Static_assert(
        sizeof(struct x64_rar_raw_pcid_inval) == 28,
        "x64 RAR PCID Invalidation Payload is not exactly 28 bytes!"
        );

struct __packed x64_rar_raw_ept_inval {
    uint8_t subtype : 3;
    uint64_t __mbz_0 : 64;
    uint64_t __mbz_1 : 29;
    uint64_t eptp : 64;
    uint64_t __mbz_2 : 64;
};
_Static_assert(
        sizeof(struct x64_rar_raw_ept_inval) == 28,
        "x64 RAR EPT Invalidation Payload is not exactly 28 bytes!"
        );

struct __packed x64_rar_raw_vpid_inval {
    uint8_t subtype : 3;
    uint8_t stride : 2;
    uint8_t num_pages : 6;
    uint64_t __mbz_0 : 64;
    uint64_t __mbz_1 : 21;
    uint32_t vpid : 32;
    uint32_t __mbz_2 : 32;
    uint64_t linear_addr : 64;
};
_Static_assert(
        sizeof(struct x64_rar_raw_vpid_inval) == 28,
        "x64 RAR VPID Invalidation Payload is not exactly 28 bytes!"
        );

struct __packed x64_rar_raw_msr_write {
    uint16_t msr_index : 11;
    uint64_t __mbz_0 : 64;
    uint64_t __mbz_1 : 21;
    uint64_t msr_data : 64;
    uint64_t __mbz_2 : 64;
};
_Static_assert(
        sizeof(struct x64_rar_raw_msr_write) == 28,
        "x64 RAR MSR Write Payload is not exactly 28 bytes!"
        );

struct __packed x64_rar_raw
{
    uint8_t __sw_avail_0;
    uint8_t type;
    uint16_t __mbz_0;
    union {
        struct x64_rar_raw_page_inval page_inval;
        struct x64_rar_raw_pcid_inval pcid_inval;
        struct x64_rar_raw_ept_inval ept_inval;
        struct x64_rar_raw_vpid_inval vpid_inval;
        struct x64_rar_raw_msr_write msr_write;
        uint8_t raw[28];
    } type_spec;
    uint8_t __sw_avail_1[32];
};
_Static_assert(
        sizeof(struct x64_rar_raw) == 64,
        "x64 RAR Payload Structure is not exactly 64 bytes!"
        );

