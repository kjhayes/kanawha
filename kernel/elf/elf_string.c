
#include <kanawha/init.h>
#include <elf/elf.h>
#include <elf/elf_string.h>

const char *
elf_get_class_string(unsigned char class) {
    const char *ret = "Unknown";
    switch(class) {
#define ELF_CLASS_STR_CASE(ENUM,VAL,STR,...)\
        case VAL:\
            ret = STR;\
            break;
        ELFCLASS_XLIST(ELF_CLASS_STR_CASE)
#undef ELF_CLASS_STR_CASE
        default:
            break;
    }
    return ret;
}

const char *
elf_get_data_string(unsigned char data) {
    const char *ret = "Unknown";
    switch(data) {
#define ELF_DATA_STR_CASE(ENUM,VAL,STR,...)\
        case VAL:\
            ret = STR;\
            break;
        ELFDATA_XLIST(ELF_DATA_STR_CASE)
#undef ELF_DATA_STR_CASE
        default:
            break;
    }
    return ret;
}

const char *
elf_get_version_string(uint32_t version) {
    const char *ret = "Unknown";
    switch(version) {
#define ELF_EV_STR_CASE(ENUM,VAL,STR,...)\
        case VAL:\
            ret = STR;\
            break;
        EV_XLIST(ELF_EV_STR_CASE)
#undef ELF_EV_STR_CASE
        default:
            break;
    }
    return ret;
}

const char *
elf_get_osabi_string(unsigned char osabi) {
    const char *ret = "Unknown";
    switch(osabi) {
#define ELF_OSABI_STR_CASE(ENUM,VAL,STR,...)\
        case VAL:\
            ret = STR;\
            break;
        ELFOSABI_XLIST(ELF_OSABI_STR_CASE)
#undef ELF_OSABI_STR_CASE
        default:
            break;
    }
    return ret;
}

const char *
elf_get_abi_version_string(unsigned char abi_version) {
    const char *ret = "Unknown";
    switch(abi_version) {
#define ELF_ABI_VERSION_STR_CASE(ENUM,VAL,STR,...)\
        case VAL:\
            ret = STR;\
            break;
        ELFABIVERSION_XLIST(ELF_ABI_VERSION_STR_CASE)
#undef ELF_ABI_VERSION_STR_CASE
        default:
            break;
    }
    return ret;
}

const char *
elf_get_type_string(uint16_t type) {
    const char *ret = "Unknown";
    switch(type) {
#define ELF_TYPE_STR_CASE(ENUM,VAL,STR,...)\
        case VAL:\
            ret = STR;\
            break;
        ET_XLIST(ELF_TYPE_STR_CASE)
#undef ELF_TYPE_STR_CASE
        default:
            break;
    }
    return ret;
}

const char *
elf_get_machine_string(uint16_t machine) {
    const char *ret = "Unknown";
    switch(machine) {
#define ELF_MACHINE_STR_CASE(ENUM,VAL,STR,...)\
        case VAL:\
            ret = STR;\
            break;
        EM_XLIST(ELF_MACHINE_STR_CASE)
#undef ELF_MACHINE_STR_CASE
        default:
            break;
    }
    return ret;
}

const char *
elf_get_phdr_type_string(uint32_t phdr_type) {
    const char *ret = "Unknown";
    switch(phdr_type) {
#define ELF_PT_STR_CASE(ENUM,VAL,STR,...)\
        case VAL:\
            ret = STR;\
            break;
        PT_XLIST(ELF_PT_STR_CASE)
#undef ELF_PT_STR_CASE
        default:
            break;
    }
    return ret;
}

