#ifndef __KANAWHA_DEVTREE_FLAT_H__
#define __KANAWHA_DEVTREE_FLAT_H__

#include <kanawha/types.h>
#include <kanawha/pointer.h>
#include <devtree/types.h>

#define FDT_MAGIC 0xd00dfeed

struct fdt_header {
    fdt32_t magic;
    fdt32_t totalsize;
    fdt32_t off_dt_struct;
    fdt32_t off_dt_strings;
    fdt32_t off_mem_rsvmap;
    fdt32_t version;
    fdt32_t last_comp_version;
    fdt32_t boot_cpuid_phys;
    fdt32_t size_dt_strings;
    fdt32_t size_dt_struct;
};

struct fdt_reserve_entry {
    fdt64_t address;
    fdt64_t size;
};

#define FDT_BEGIN_NODE ((fdt32_t)0x1)
#define FDT_END_NODE   ((fdt32_t)0x2)
#define FDT_PROP       ((fdt32_t)0x3)
#define FDT_NOP        ((fdt32_t)0x4)
#define FDT_END        ((fdt32_t)0x9)

struct fdt_node {
    fdt32_t token; // FDT_BEGIN_NODE
    char unitname[];
};

struct fdt_property {
    fdt32_t token; // FDT_PROP
    fdt32_t len;
    fdt32_t nameoff;
    uint8_t data[];
};

struct fdt {
    struct fdt_header hdr;
    uint8_t data[];
};

// Returns 0 if this FDT passes basic inspection (primarily magic numbers)
// Returns negative errno on failure
int
fdt_check_header(struct fdt *fdt);

// Return the size of the device tree in bytes
size_t
fdt_size(struct fdt *fdt);

// Returns the next token of any type (including NOP)
// Returns NULL if there are no more tokens
fdt32_t *
fdt_exact_next_token(struct fdt* fdt, fdt32_t* token);

// Same as fdt_exact_next_token but will skip over FDT_NOP tokens
// and early exit when it sees an FDT_END token
fdt32_t *
fdt_next_token(struct fdt *fdt, fdt32_t *token);

// Get the first node in the device tree
// Returns NULL if the device tree is empty
struct fdt_node *
fdt_first_node(struct fdt *fdt);

// Get the next node or subnode in the device tree (ignoring depth)
// Returns NULL if there is not a node after "node"
struct fdt_node *
fdt_next_node(struct fdt *fdt, struct fdt_node *node);

char *
fdt_node_unitname(
        struct fdt *fdt,
        struct fdt_node *node);

// Returns NULL if node has no parent
// Note: This function needs to scan the entire
//       tree and so it is very slow
struct fdt_node *
fdt_node_find_parent(
        struct fdt *fdt,
        struct fdt_node *node);

// Determine the #address-cells value which applies to this node
uint32_t
fdt_node_address_cells(
        struct fdt *fdt,
        struct fdt_node *node);

// Determine the #size-cells value which applies to this node
uint32_t
fdt_node_size_cells(
        struct fdt *fdt,
        struct fdt_node *node);

// Get the first subnode of this node
// Returns NULL if this node has no subnodes
struct fdt_node *
fdt_node_first_subnode(
        struct fdt *fdt,
        struct fdt_node *node);

// Get the next subnode
// (the next node at the same depth which has the same parent as this node)
// Returns NULL if no such node exists
struct fdt_node *
fdt_node_next_subnode(
        struct fdt *fdt,
        struct fdt_node *subnode);

// Get the first property of this node
// Returns NULL if this node has no properties
struct fdt_property *
fdt_node_first_property(
        struct fdt *fdt,
        struct fdt_node *node);

// Get the next property in this node
// Returns NULL if there is no next property
struct fdt_property *
fdt_node_next_property(
        struct fdt *fdt,
        struct fdt_property *property);

// Returns a pointer to the name of the property
char *
fdt_property_name(
        struct fdt *fdt,
        struct fdt_property *property);

// Get the size of the property data
size_t
fdt_property_size(
        struct fdt *fdt,
        struct fdt_property *property);

// Return a pointer to this property's data
void *
fdt_property_data(
        struct fdt *fdt,
        struct fdt_property *property);

// Returns 0 if the unitname's match, non-zero otherwise
//
// Ignores characters after "@" in the unit name,
// so "memory@0x10000" and "memory@0x0" will both match "memory"
int
fdt_compare_unitname(
        const char *s0,
        const char *s1);

// Returns NULL if the property cannot be found
// Ignores characters after "@" in the unit name,
// so "memory@0x10000" and "memory@0x0" will both match "memory"
struct fdt_node *
fdt_find_node_by_unitname(
        struct fdt *fdt,
        const char *unitname);

// Returns NULL if the property cannot be found
struct fdt_property *
fdt_find_property_by_name(
        struct fdt *fdt,
        struct fdt_node *node,
        const char *name);

size_t
fdt_node_reg_count(
        struct fdt *fdt,
        struct fdt_node *node);

int
fdt_node_read_reg(
        struct fdt *fdt,
        struct fdt_node *node,
        size_t buflen,
        void __phys **addr_buf,
        size_t *size_buf);

int
dump_fdt(
        printk_f *printer,
        struct fdt *fdt);

#endif
