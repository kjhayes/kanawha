#ifndef __KANAWHA__ELF_STRING_H__
#define __KANAWHA__ELF_STRING_H__

#include <elf/elf.h>
#include <kanawha/stdint.h>

const char *elf_get_class_string(unsigned char cls);
const char *elf_get_data_string(unsigned char data);
const char *elf_get_version_string(uint32_t version);
const char *elf_get_osabi_string(unsigned char osabi);
const char *elf_get_abi_version_string(unsigned char abi_version);
const char *elf_get_type_string(uint16_t type);
const char *elf_get_machine_string(uint16_t machine);
const char *elf_get_phdr_type_string(uint32_t ptype);

#endif
