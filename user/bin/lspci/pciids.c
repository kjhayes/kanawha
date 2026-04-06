
#include "pciids.h"
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define BUFLEN 0x100

static FILE *pciid_file = NULL;

static int found_vendor = 0;
static int found_device = 0;
static int found_subsystem = 0;
static int found_class = 0;
static int found_subclass = 0;

static int currently_class = 0;
static int32_t current_vendor = -1;
static off_t vendor_name_offset = -1;
static int32_t current_device = -1;
static off_t device_name_offset = -1;
static int32_t current_subsystem_vendor = -1;
static int32_t current_subsystem_device = -1;
static off_t subsystem_name_offset = -1;

static int eof = 0;
static off_t line_tell = 0;
static char linebuf[BUFLEN+1] = {0};

int init_pciids(const char *path)
{
    pciid_file = fopen(path, "r");
    if(pciid_file == NULL) {
        return -ENXIO;
    }
    fseek(pciid_file, 0, SEEK_SET);
    return 0;
}
int deinit_pciids(void)
{
    if(pciid_file != NULL) {
        fclose(pciid_file);
    }
    return 0;
}

static int
begin_id_iterator(void)
{
    currently_class = 0;
    current_vendor = -1;
    current_device = -1;
    current_subsystem_vendor = -1;
    current_subsystem_device = -1;

    found_vendor = 0;
    found_device = 0;
    found_subsystem = 0;
    found_class = 0;
    found_subclass = 0;

    vendor_name_offset = -1;
    device_name_offset = -1;
    subsystem_name_offset = -1;

    memset(linebuf, 0, BUFLEN);
    fseek(pciid_file, 0, SEEK_SET);
    line_tell = ftell(pciid_file);
    return 0;
}

// returns 0 on eof, 1 on successful step, <0 on error

static inline int32_t
hex_chars(char *hex) {
    int32_t final = 0;
    for(int i = 0; i < 4; i++) {
        char c = hex[i];
        int32_t val;
        if('0' <= c && c <= '9') {
            val = c - '0';
        }
        else if('a' <= c && c <= 'f') {
            val = 10 + (c-'a');
        }
        else if('A' <= c && c <= 'F') {
            val = 10 + (c-'A');
        }
        else {
            fprintf(stderr, "pci.ids: invalid hexadecimal string \"%c%c%c%c\"!\n",
                    hex[0], hex[1], hex[2], hex[3]);
            return -1;
        }

        int32_t order = 1<<(12-(i*4));
        final += (order * val);
    }
    return final;
}

static int
step_id_iterator(void) {
    if(found_vendor && found_device && found_subsystem && found_class && found_subclass) {
        // Return EOF early if we have found everything we need
        return 0;
    }
    if(pciid_file == NULL) {
        // EOF immediately
        printf("step_id_iterator: pciid_file is NULL!\n");
        return 0;
    }
    while(1) {
        // Step over empty lines
        if(strlen(linebuf) == 0) {
            line_tell = ftell(pciid_file);
            char *r = fgets(linebuf, BUFLEN, pciid_file);
            if(r == NULL) {
                // End of stream
                return 0;
            }
            continue;
        }
        // Step over any comments
        if(linebuf[0] == '#') {
            line_tell = ftell(pciid_file);
            char *r = fgets(linebuf, BUFLEN, pciid_file);
            if(r == NULL) {
                // End of stream
                return 0;
            }
            continue;
        }

        { // Check for completely whitespace lines...
          // Shouldn't be valid but still...
        char *iter = linebuf;
        while(isspace(*iter)) {
            iter++;
        }
        if(*iter == '\0') {
            line_tell = ftell(pciid_file);
            char *r = fgets(linebuf, BUFLEN, pciid_file);
            if(r == NULL) {
                // End of stream
                return 0;
            }
            continue;
        }
        }

        // linebuf should have a line with content
        if(linebuf[0] == '\t') {
            if(currently_class) {
                // Subclass
            } else {
                // Device or Subsystem
                if(current_vendor == -1) {
                    fprintf(stderr, "malformed pci.ids file (found device/subsystem before any vendor)!\n");
                    return 0;
                }
                if(linebuf[1] == '\t') {
                    // Subsystem ID Line
                    if(!found_subsystem) {
                        if(current_device == -1) {
                            fprintf(stderr, "malformed pci.ids file (found subsystem before any device)!\n");
                            return 0;
                        }
                        char *vendor_hex = linebuf+2;
                        char *device_hex = vendor_hex + 4 + 1;
                        int32_t subsystem_vendor = hex_chars(vendor_hex);
                        int32_t subsystem_device = hex_chars(device_hex);
                        if(subsystem_vendor < 0 || subsystem_device < 0) {
                            fprintf(stderr, "malformed pci.ids file (failed to read subsystem hex ids from line: \"%s\"\n",
                                    linebuf);
                            return 0;
                        }
                        current_subsystem_vendor = subsystem_vendor;
                        current_subsystem_device = subsystem_device;
                        if(subsystem_vendor >= 0 && subsystem_device >= 0) {
                            subsystem_name_offset = line_tell + 2 + 4 + 1 + 4 + 1;
                        }
                    }
                } else {
                    // Device ID Line
                    if(!found_device) {
                        char *hex = linebuf+1;
                        int32_t device = hex_chars(hex);
                        if(device < 0) {
                            fprintf(stderr, "malformed pci.ids file (failed to read device hex id from line: \"%s\"\n",
                                    linebuf);
                            return 0;
                        }
                        current_device = device;
                        if(device >= 0) {
                            device_name_offset = line_tell + 1 + 4 + 1;
                        }
                    } else {
                        // The subsystem does not exist...
                        found_subsystem = 1;
                    }
                }
            }
        } 
        else if(linebuf[0] == 'C') {
            // Class line
            currently_class = 1;
        } else {
            // Vendor ID Line
            if(!found_vendor) {
                currently_class = 0;
                char *hex = linebuf+0;
                int32_t vendor = hex_chars(hex);
                if(vendor < 0) {
                    fprintf(stderr, "malformed pci.ids file (failed to read vendor hex id from line: \"%s\"\n",
                            linebuf);
                    return 0;
                }
                char *str = hex + 4;
                current_vendor = vendor;
                if(vendor >= 0) {
                    vendor_name_offset = line_tell + 0 + 4 + 1;
                }
            } else {
                found_device = 1;
                found_subsystem = 1;
            }
        }

        line_tell = ftell(pciid_file);
        char *r = fgets(linebuf, BUFLEN, pciid_file);
        if(r == NULL) {
            // End of stream, but we can ignore it
        }
        return 1;
    }
}

struct pciid *
lookup_pciid(
        uint16_t vendor,
        uint16_t device,
        uint32_t cls,
        uint16_t subsystem_vendor,
        uint16_t subsystem_id)
{
    struct pciid *id;
    id = malloc(sizeof(*id));
    if(id == NULL) {
        return NULL;
    }

    id->vendor = NULL;
    id->vendor_valid = 0;

    id->device = NULL;
    id->device_valid = 0;

    id->subsystem = NULL;
    id->subsystem_valid = 0;

    id->class = NULL;
    id->class_valid = 0;

    id->subclass = NULL;
    id->subclass_valid = 0;

    begin_id_iterator();
    found_class = 1;
    found_subclass = 1;
    while(step_id_iterator()) {
        if(currently_class) {
            // TODO
        } else {
            if(current_vendor == vendor) {
                found_vendor = 1;
                if(current_device == device) {
                    found_device = 1;
                    if((current_subsystem_vendor == subsystem_vendor)
                     &&(current_subsystem_device == subsystem_id)) {
                        found_subsystem = 1;
                    }
                }
            }
        }
    }

    char buffer[BUFLEN];
    if(found_vendor) {
        fseek(pciid_file, vendor_name_offset, SEEK_SET);
        fgets(buffer, BUFLEN, pciid_file);
        buffer[BUFLEN-1] = '\0';
        id->vendor = strdup(buffer);
        if(id->vendor) {
            id->vendor_valid = 1;
            ssize_t i = strlen(id->vendor)-1;
            while(i >= 0 && isspace(id->vendor[i])) {
                ((char*)id->vendor)[i] = '\0';
            }
        }
    }
    if(found_device) {
        fseek(pciid_file, device_name_offset, SEEK_SET);
        fgets(buffer, BUFLEN, pciid_file);
        buffer[BUFLEN-1] = '\0';
        id->device = strdup(buffer);
        if(id->device) {
            id->device_valid = 1;
            ssize_t i = strlen(id->device)-1;
            while(i >= 0 && isspace(id->device[i])) {
                ((char*)id->device)[i] = '\0';
            }
        }
    }
    if(found_subsystem) {
        fseek(pciid_file, subsystem_name_offset, SEEK_SET);
        fgets(buffer, BUFLEN, pciid_file);
        buffer[BUFLEN-1] = '\0';
        id->subsystem = strdup(buffer);
        if(id->subsystem) {
            id->subsystem_valid = 1;
            ssize_t i = strlen(id->subsystem)-1;
            while(i >= 0 && isspace(id->subsystem[i])) {
                ((char*)id->subsystem)[i] = '\0';
            }
        }
    }
    return id;
}

int
free_pciid(
        struct pciid *id)
{
    if(id == NULL) {
        return 0;
    }

    if(id->vendor_valid) {
        free((void*)id->vendor);
    }
    if(id->device_valid) {
        free((void*)id->device);
    }
    if(id->subsystem_valid) {
        free((void*)id->subsystem);
    }
    if(id->class_valid) {
        free((void*)id->class);
    }
    if(id->subclass_valid) {
        free((void*)id->subclass);
    }

    free(id);
    return 0;
}

