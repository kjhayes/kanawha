
#include <kanawha/printk.h>
#include <kanawha/vmem.h>
#include <kanawha/spinlock.h>
#include <kanawha/stree.h>
#include <kanawha/string.h>
#include <kanawha/slab.h>
#include <kanawha/stddef.h>
#include <kanawha/init.h>
#include <acpi/acpi.h>

static DECLARE_SPINLOCK(acpi_table_lock);
int found_global_xsdp = 0;
int found_global_rsdp = 0;
static struct acpi_xsdp global_xsdp = { 0 };
static struct acpi_rsdp global_rsdp = { 0 };
static struct acpi_xsdt *global_xsdt = NULL;
static struct acpi_rsdt *global_rsdt = NULL;


static DECLARE_STREE(acpi_table_tree);

struct acpi_table_ptr {
    struct acpi_table_hdr *table;
    struct stree_node tree_node;
    char signature_str[5];
};

static struct slab_allocator *acpi_table_ptr_slab_allocator;
static uint8_t acpi_table_ptr_slab_buffer[sizeof(struct acpi_table_ptr) * 32];

static int
acpi_register_table(struct acpi_table_hdr *table)
{
    struct stree_node *node;
    char buf[5];
    memcpy(buf, table->signature, 4);
    buf[4] = '\0';
    node = stree_get(&acpi_table_tree, buf);
    if(node != NULL) {
        wprintk("Trying to register multiple versions of the ACPI \"%s\" Table! (ignoring)\n", buf);
        return 0;
    }

    struct acpi_table_ptr *ptr;
    ptr = slab_alloc(acpi_table_ptr_slab_allocator);
    if(ptr == NULL) {
        eprintk("Failed to allocate ACPI table node!\n");
        return -ENOMEM;
    }

    ptr->table = table;
    memcpy(ptr->signature_str, buf, 5);
    ptr->tree_node.key = ptr->signature_str;

    stree_insert(&acpi_table_tree, &ptr->tree_node);

    printk("Registered ACPI Table: %s\n", ptr->signature_str);

    return 0;
}

static int
acpi_load_tables(void)
{
    acpi_table_ptr_slab_allocator =
        create_static_slab_allocator(
                acpi_table_ptr_slab_buffer,
                sizeof(acpi_table_ptr_slab_buffer),
                sizeof(struct acpi_table_ptr),
                alignof(struct acpi_table_ptr));

    if(acpi_table_ptr_slab_allocator == NULL) {
        return -ENOMEM;
    }

    if(global_xsdt != NULL) {
        size_t num_tables =
            (global_xsdt->hdr.length - sizeof(struct acpi_table_hdr))
            / sizeof(uint64_t);
        printk("Loading %lu Tables from XSDT\n", num_tables);
        for(size_t i = 0; i < num_tables; i++) {
            uint64_t phys_ptr = global_xsdt->table_ptrs[i];
            void *table = (void*)__va(phys_ptr);
            int res = acpi_register_table(table);
            if(res) {
                eprintk("Failed to register APCI table at address (%p)!\n",
                        table);
                return res;
            }
        }
    } else if(global_rsdt != NULL) {
        size_t num_tables =
            (global_rsdt->hdr.length - sizeof(struct acpi_table_hdr))
            / sizeof(uint64_t);
        printk("Loading %lu Tables from RSDT\n", num_tables);
        for(size_t i = 0; i < num_tables; i++) {
            uint32_t phys_ptr = global_rsdt->table_ptrs[i];
            void *table = (void*)__va(phys_ptr);
            int res = acpi_register_table(table);
            if(res) {
                eprintk("Failed to register APCI table at address (%p)!\n",
                        table);
                return res;
            }
        }
    } else {
        eprintk("ACPI Trying to Load Tables from RSDP without XSDT or RSDT!\n");
        return -EINVAL;
    }

    return 0;
}
declare_init_desc(post_vmem, acpi_load_tables, "Loading ACPI Tables");

int
acpi_provide_rsdp(struct acpi_rsdp *rsdp)
{
    spin_lock(&acpi_table_lock);
    if(found_global_rsdp) {
        spin_unlock(&acpi_table_lock);
        eprintk("ACPI provided with multiple RSDP!\n");
        return -EINVAL;
    }

    memcpy(&global_rsdp, rsdp, sizeof(struct acpi_rsdp));
    found_global_rsdp = 1;
    global_rsdt = (void*)__va(rsdp->rsdt_ptr);
    printk("ACPI RSDT: %p\n", global_rsdt);

    spin_unlock(&acpi_table_lock);
    return 0;
}

int
acpi_provide_xsdp(struct acpi_xsdp *xsdp)
{
    spin_lock(&acpi_table_lock);
    if(found_global_xsdp) {
        spin_unlock(&acpi_table_lock);
        eprintk("ACPI provided with multiple XSDP!\n");
        return -EINVAL;
    }

    memcpy(&global_xsdp, xsdp, sizeof(struct acpi_xsdp));
    found_global_xsdp = 1;
    global_xsdt = (void*)__va(xsdp->xsdt_ptr);
    printk("ACPI XSDT: %p\n", global_xsdt);

    spin_unlock(&acpi_table_lock);
    return 0;
}

struct acpi_table_hdr *
acpi_find_table(const char *signature) {
    struct acpi_table_hdr *table;
    spin_lock(&acpi_table_lock);
    struct stree_node *node;
    node = stree_get(&acpi_table_tree, signature);
    if(node == NULL) {
        table = NULL;
    } else {
        struct acpi_table_ptr *ptr =
            container_of(node, struct acpi_table_ptr, tree_node);
        table = ptr->table;
    }
    spin_unlock(&acpi_table_lock);
    return table;
}

uint32_t acpi_revision(void) {
    if(found_global_xsdp) {
        return global_xsdp.revision;
    }
    if(found_global_rsdp) {
        return global_rsdp.revision;
    }
    return 0;
}

