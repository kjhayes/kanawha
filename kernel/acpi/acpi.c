
#include <kanawha/printk.h>
#include <kanawha/vmem.h>
#include <kanawha/lock.h>
#include <kanawha/stree.h>
#include <kanawha/string.h>
#include <kanawha/slab.h>
#include <kanawha/stddef.h>
#include <kanawha/init.h>
#include <acpi/acpi.h>
#include <acpi/table.h>

#ifdef CONFIG_ACPI_SYSFS
#include <acpi/sysfs.h>
#endif

struct acpi_rsdt {
    struct acpi_table_hdr hdr;
    uint32_t table_ptrs[];
} __attribute__((packed));

struct acpi_xsdt {
    struct acpi_table_hdr hdr;
    uint64_t table_ptrs[];
} __attribute__((packed));

DEFINE_LOCAL_THREAD_LOCK(acpi_table_lock);

int found_global_xsdp = 0;
int found_global_rsdp = 0;
static struct acpi_xsdp global_xsdp = { 0 };
static struct acpi_rsdp global_rsdp = { 0 };
static struct acpi_xsdt *global_xsdt = NULL;
static struct acpi_rsdt *global_rsdt = NULL;

static DECLARE_STREE(acpi_table_tree);
static DECLARE_ILIST(acpi_ssdt_list);

// TODO: This slab allocator is not locked properly
static struct slab_allocator *acpi_table_slab_allocator;
static uint8_t acpi_table_slab_buffer[sizeof(struct acpi_table) * 32];

int
acpi_register_raw_table(struct acpi_table_data *table)
{
    int res;

    // Special Cases
    if(table->hdr.signature[0] == 'S'
    &&(table->hdr.signature[1] == 'S')
    &&(table->hdr.signature[2] == 'D')
    &&(table->hdr.signature[3] == 'T'))
    {
        struct acpi_table *ptr;

        ptr = slab_alloc(acpi_table_slab_allocator);
        if(ptr == NULL) {
            return -ENOMEM;
        }
        ptr->table = table;
        wprintk("Ignoring ACPI SSDT Table!\n");
        return 0;
    }

    struct stree_node *node;
    char buf[5];
    memcpy(buf, table->hdr.signature, 4);
    buf[4] = '\0';
    node = stree_get(&acpi_table_tree, buf);
    if(node != NULL) {
        wprintk("Trying to register multiple versions of the ACPI \"%s\" Table! (ignoring)\n", buf);
        return 0;
    }

    struct acpi_table *ptr;
    ptr = slab_alloc(acpi_table_slab_allocator);
    if(ptr == NULL) {
        eprintk("Failed to allocate ACPI table node!\n");
        return -ENOMEM;
    }

    ptr->table = table;
    memcpy(ptr->signature_str, buf, 5);
    ptr->tree_node.key = ptr->signature_str;

    stree_insert(&acpi_table_tree, &ptr->tree_node);

#ifdef CONFIG_ACPI_SYSFS
    res = acpi_sysfs_on_register_table(ptr);
    if(res) {
        wprintk("Failed to register ACPI table with ACPI sysfs!\n");
    }
#endif

    printk("Registered ACPI Table: %s\n", ptr->signature_str);

    return 0;
}

static int
acpi_load_tables(void)
{
    acpi_table_slab_allocator =
        create_static_slab_allocator(
                acpi_table_slab_buffer,
                sizeof(acpi_table_slab_buffer),
                sizeof(struct acpi_table),
                alignof(struct acpi_table));

    if(acpi_table_slab_allocator == NULL) {
        return -ENOMEM;
    }

    if(global_xsdt != NULL) {
        size_t num_tables =
            (global_xsdt->hdr.length - sizeof(struct acpi_table_hdr))
            / sizeof(uint64_t);
        printk("Loading %lu Tables from XSDT\n", num_tables);
        for(size_t i = 0; i < num_tables; i++) {
            uint64_t phys_ptr = global_xsdt->table_ptrs[i];
            void *table = (void*)__va((void __phys *)phys_ptr);
            int res = acpi_register_raw_table(table);
            if(res) {
                eprintk("Failed to register APCI table at address (%p)!\n",
                        table);
                return res;
            }
        }
    } else if(global_rsdt != NULL) {
        size_t num_tables =
            (global_rsdt->hdr.length - sizeof(struct acpi_table_hdr))
            / sizeof(uint32_t);
        printk("Loading %lu Tables from RSDT\n", num_tables);
        for(size_t i = 0; i < num_tables; i++) {
            uint32_t phys_ptr = global_rsdt->table_ptrs[i];
            void *table = (void*)__va((void __phys *)(uintptr_t)phys_ptr);
            int res = acpi_register_raw_table(table);
            if(res) {
                eprintk("Failed to register APCI table at address (%p)!\n",
                        table);
                return res;
            }
        }
    } else {
#ifdef CONFIG_ACPI_REQUIRED
        eprintk("ACPI Tried to Load Tables from RSDP without XSDT or RSDT!\n");
        return -EINVAL;
#else
        return 0;
#endif
    }

    return 0;
}
declare_init_desc(post_vmem, acpi_load_tables, "Loading ACPI Tables");

int
acpi_provide_rsdp(struct acpi_rsdp *rsdp)
{
    acpi_table_lock_acquire();
    if(found_global_rsdp) {
        acpi_table_lock_release();
        eprintk("ACPI provided with multiple RSDP!\n");
        return -EINVAL;
    }

    memcpy(&global_rsdp, rsdp, sizeof(struct acpi_rsdp));
    found_global_rsdp = 1;
    global_rsdt = (void*)__va((void __phys *)(uintptr_t)rsdp->rsdt_ptr);
    printk("ACPI RSDT: %p\n", global_rsdt);

    acpi_table_lock_release();
    return 0;
}

int
acpi_provide_xsdp(struct acpi_xsdp *xsdp)
{
    acpi_table_lock_acquire();
    if(found_global_xsdp) {
        acpi_table_lock_release();
        eprintk("ACPI provided with multiple XSDP!\n");
        return -EINVAL;
    }

    memcpy(&global_xsdp, xsdp, sizeof(struct acpi_xsdp));
    found_global_xsdp = 1;
    global_xsdt = (void*)__va((void __phys *)xsdp->xsdt_ptr);
    printk("ACPI XSDT: %p\n", global_xsdt);

    acpi_table_lock_release();
    return 0;
}

struct acpi_table *
acpi_find_table(const char *signature) {
    struct acpi_table *table;
    acpi_table_lock_acquire();
    struct stree_node *node;
    node = stree_get(&acpi_table_tree, signature);
    if(node == NULL) {
        table = NULL;
    } else {
        table = container_of(node, struct acpi_table, tree_node);
    }
    acpi_table_lock_release();
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

