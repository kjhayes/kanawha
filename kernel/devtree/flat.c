
#include <devtree/devtree.h>
#include <devtree/flat.h>
#include <devtree/types.h>

#include <kanawha/string.h>

int
fdt_check_header(struct fdt *fdt)
{
    uint32_t magic = fdttoh32(fdt->hdr.magic);
    if(magic != FDT_MAGIC)
    {
        return -EINVAL;
    }
    return 0;
}

size_t
fdt_size(struct fdt *fdt)
{
    uint32_t size = fdttoh32(fdt->hdr.totalsize);
    return (size_t)size;
}

fdt32_t *
fdt_exact_next_token(struct fdt *fdt, fdt32_t *token)
{
    struct fdt_node *node;
    struct fdt_property *prop;
    size_t str_len;
    size_t cell_len;

    uint32_t val = fdttoh32(*token);

    switch(val)
    {
    case FDT_NOP:
        token++;
        break;
    case FDT_END_NODE:
        token++;
        break;
    case FDT_BEGIN_NODE:
        node = (struct fdt_node *)token;
        str_len = (size_t)strlen(node->unitname) + 1;
        // Align to 4 bytes
        cell_len = (str_len >> 2) + ((str_len & 3) != 0);
        // extra 1 is for the "token" field
        token += (1 + cell_len);
        break;
    case FDT_PROP:
        prop = (struct fdt_property *)token;
        str_len = fdttoh32(prop->len);
        // Align to 4 bytes
        cell_len = (str_len >> 2) + ((str_len & 3) != 0);
        // extra 3 is for "token", "len" and "name_offset" fields
        token += (3 + cell_len);
        break;
    case FDT_END:
    default:
        token = NULL;
        break;
    }

    return token;
}

fdt32_t *
fdt_next_token(struct fdt *fdt, fdt32_t *token)
{
    fdt32_t *iter = token;
    while(iter)
    {
        iter = fdt_exact_next_token(fdt, iter);
        if(iter == NULL)
        {
            return NULL;
        }
        switch(fdttoh32(*iter))
        {
        case FDT_NOP:
            continue;
        case FDT_END:
            return NULL;
        default:
            return iter;
        }
    }
    return NULL;
}

struct fdt_node *
fdt_first_node(struct fdt *fdt)
{
    DEBUG_ASSERT(fdt_check_header(fdt) == 0);

    uint32_t offset = fdttoh32(fdt->hdr.off_dt_struct);
    fdt32_t *token = (fdt32_t *)(((void *)fdt) + offset);
    while(token && fdttoh32(*token) != FDT_BEGIN_NODE)
    {
        token = fdt_next_token(fdt, token);
    }
    if(token == NULL)
    {
        return NULL;
    }
    return container_of(token, struct fdt_node, token);
}

struct fdt_node *
fdt_next_node(struct fdt *fdt, struct fdt_node *node)
{
    fdt32_t *token = &node->token;
    do
    {
        token = fdt_next_token(fdt, token);
    } while(token && fdttoh32(*token) != FDT_BEGIN_NODE);
    if(token == NULL)
    {
        return NULL;
    }
    return container_of(token, struct fdt_node, token);
}

char *
fdt_node_unitname(struct fdt *fdt, struct fdt_node *node)
{
    return node->unitname;
}

static struct fdt_node *
__fdt_node_find_parent_helper(struct fdt *fdt,
                              struct fdt_node *parent,
                              struct fdt_node *child)
{
    struct fdt_node *iter = fdt_node_first_subnode(fdt, parent);
    while(iter)
    {
        if(iter == child)
        {
            return parent;
        }
        struct fdt_node *rec = __fdt_node_find_parent_helper(fdt, iter, child);
        if(rec != NULL)
        {
            return rec;
        }
        iter = fdt_node_next_subnode(fdt, iter);
    }
    return NULL;
}

struct fdt_node *
fdt_node_find_parent(struct fdt *fdt, struct fdt_node *node)
{
    struct fdt_node *root = fdt_first_node(fdt);
    if(root == NULL || node == root)
    {
        return NULL;
    }
    return __fdt_node_find_parent_helper(fdt, root, node);
}

uint32_t
fdt_node_address_cells(struct fdt *fdt, struct fdt_node *node)
{
    uint32_t address_cells = 2;
    struct fdt_node *parent = fdt_node_find_parent(fdt, node);
    if(parent == NULL)
    {
        return address_cells;
    }

    struct fdt_property *prop =
        fdt_find_property_by_name(fdt, parent, "#address-cells");
    if(prop == NULL)
    {
        return address_cells;
    }

    size_t len = fdt_property_size(fdt, prop);
    if(len != 4)
    {
        wprintk("fdt_node_address_cells: found #address-cells property but "
                "len=%lu!\n",
                (ul_t)len);
        return address_cells;
    }

    fdt32_t *data = fdt_property_data(fdt, prop);
    address_cells = fdttoh32(*data);

    return address_cells;
}

uint32_t
fdt_node_size_cells(struct fdt *fdt, struct fdt_node *node)
{
    uint32_t size_cells = 1;
    struct fdt_node *parent = fdt_node_find_parent(fdt, node);
    if(parent == NULL)
    {
        return size_cells;
    }

    struct fdt_property *prop =
        fdt_find_property_by_name(fdt, parent, "#size-cells");
    if(prop == NULL)
    {
        return size_cells;
    }

    size_t len = fdt_property_size(fdt, prop);
    if(len != 4)
    {
        wprintk("fdt_node_size_cells: found #size-cells property but "
                "len=%lu!\n",
                (ul_t)len);
        return size_cells;
    }

    fdt32_t *data = fdt_property_data(fdt, prop);
    size_cells = fdttoh32(*data);

    return size_cells;
}

struct fdt_node *
fdt_node_first_subnode(struct fdt *fdt, struct fdt_node *node)
{
    fdt32_t *token = &node->token;

    do
    {
        token = fdt_next_token(fdt, token);
        uint32_t value = fdttoh32(*token);
        switch(value)
        {
        case FDT_BEGIN_NODE:
            return container_of(token, struct fdt_node, token);
        case FDT_END_NODE:
            return NULL;
        default:
            break;
        }
    } while(token);

    return NULL;
}

struct fdt_node *
fdt_node_next_subnode(struct fdt *fdt, struct fdt_node *subnode)
{
    fdt32_t *token = &subnode->token;
    int depth = 1;

    do
    {
        token = fdt_next_token(fdt, token);
        if(token == NULL)
        {
            break;
        }
        uint32_t value = fdttoh32(*token);
        switch(value)
        {
        case FDT_BEGIN_NODE:
            if(depth == 0)
            {
                return container_of(token, struct fdt_node, token);
            }
            depth++;
            break;
        case FDT_END_NODE:
            depth--;
            if(depth < 0)
            {
                return NULL;
            }
            break;
        default:
            break;
        }
    } while(token);

    return NULL;
}

struct fdt_property *
fdt_node_first_property(struct fdt *fdt, struct fdt_node *node)
{
    fdt32_t *token = &node->token;
    int depth = 0;
    do
    {
        token = fdt_next_token(fdt, token);
        uint32_t value = fdttoh32(*token);
        switch(value)
        {
        case FDT_BEGIN_NODE:
            depth++;
            break;
        case FDT_END_NODE:
            if(depth == 0)
            {
                return NULL;
            }
            depth--;
            break;
        case FDT_PROP:
            if(depth == 0)
            {
                return container_of(token, struct fdt_property, token);
            }
            break;
        default:
            break;
        }
    } while(token);

    return NULL;
}

struct fdt_property *
fdt_node_next_property(struct fdt *fdt, struct fdt_property *property)
{
    fdt32_t *token = &property->token;
    int depth = 0;
    do
    {
        token = fdt_next_token(fdt, token);
        uint32_t value = fdttoh32(*token);
        switch(value)
        {
        case FDT_BEGIN_NODE:
            depth++;
            break;
        case FDT_END_NODE:
            if(depth == 0)
            {
                return NULL;
            }
            depth--;
            break;
        case FDT_PROP:
            if(depth == 0)
            {
                return container_of(token, struct fdt_property, token);
            }
            break;
        default:
            break;
        }
    } while(token);

    return NULL;
}

char *
fdt_property_name(struct fdt *fdt, struct fdt_property *property)
{
    uint32_t strings_offset = fdttoh32(fdt->hdr.off_dt_strings);
    char *strings_data = (((void *)fdt) + strings_offset);

    uint32_t offset = fdttoh32(property->nameoff);
    char *string = strings_data + offset;

    return string;
}

size_t
fdt_property_size(struct fdt *fdt, struct fdt_property *property)
{
    uint32_t len = fdttoh32(property->len);
    return (size_t)len;
}

void *
fdt_property_data(struct fdt *fdt, struct fdt_property *property)
{
    return (void *)property->data;
}

int
fdt_compare_unitname(const char *s0, const char *s1)
{
    while(*s0 && *s1 && (*s0 != '@') && (*s1 != '@'))
    {
        if(*s0 != *s1)
        {
            // Different Character
            return -1;
        }
        s0++;
        s1++;
    }

    if(!((*s0 == '\0' || *s0 == '@') && (*s1 == '\0' || *s1 == '@')))
    {
        // One ended earlier than the other
        return -1;
    }

    return 0; // A Match!
}

struct fdt_node *
fdt_find_node_by_unitname(struct fdt *fdt, const char *unitname)
{
    struct fdt_node *iter = fdt_first_node(fdt);
    while(iter)
    {
        char *iter_unitname = fdt_node_unitname(fdt, iter);
        if(fdt_compare_unitname(unitname, iter_unitname) == 0)
        {
            return iter;
        }
        iter = fdt_next_node(fdt, iter);
    }
    return NULL;
}

struct fdt_property *
fdt_find_property_by_name(struct fdt *fdt,
                          struct fdt_node *node,
                          const char *name)
{
    struct fdt_property *iter = fdt_node_first_property(fdt, node);
    while(iter)
    {
        char *prop_name = fdt_property_name(fdt, iter);
        if(strcmp(name, prop_name) == 0)
        {
            return iter;
        }
        iter = fdt_node_next_property(fdt, iter);
    }
    return NULL;
}

size_t
fdt_node_reg_count(struct fdt *fdt, struct fdt_node *node)
{
    uint32_t addr_cells = fdt_node_address_cells(fdt, node);
    uint32_t size_cells = fdt_node_size_cells(fdt, node);

    size_t entry_data_size = (addr_cells + size_cells) * 4;

    struct fdt_property *prop = fdt_find_property_by_name(fdt, node, "reg");
    if(prop == NULL)
    {
        return 0;
    }

    size_t prop_size = fdt_property_size(fdt, prop);
    return prop_size / entry_data_size;
}

int
fdt_node_read_reg(struct fdt *fdt,
                  struct fdt_node *node,
                  size_t buflen,
                  void __phys **addr_buf,
                  size_t *size_buf)
{
    if(buflen == 0)
    {
        return 0;
    }

    struct fdt_property *reg = fdt_find_property_by_name(fdt, node, "reg");
    if(reg == NULL)
    {
        return -ENXIO;
    }

    fdt32_t *cells = fdt_property_data(fdt, reg);
    if(cells == NULL)
    {
        return -EINVAL;
    }

    size_t prop_data_len = fdt_property_size(fdt, reg);
    fdt32_t *prop_end = cells + (prop_data_len / 4);

    uint32_t addr_cells = fdt_node_address_cells(fdt, node);
    uint32_t size_cells = fdt_node_size_cells(fdt, node);

    dprintk("fdt_node_read_reg (addr_cells=0x%lx, size_cells=0x%lx)\n",
            (ul_t)addr_cells,
            (ul_t)size_cells);

    for(size_t i = 0; i < buflen; i++)
    {
        if(cells > prop_end)
        {
            addr_buf[i] = NULL;
            size_buf[i] = 0;
            continue;
        }

        void *addr_ptr = (void *)cells;
        switch(addr_cells)
        {
        case 0:
            addr_buf[i] = NULL;
            break;
        case 1:
            addr_buf[i] =
                (void __phys *)(uintptr_t)fdttoh32(*(fdt32_t *)addr_ptr);
            break;
        case 2:
            addr_buf[i] =
                (void __phys *)(uintptr_t)fdttoh64(*(fdt64_t *)addr_ptr);
            break;
        default:
            return -EINVAL;
        }

        void *size_ptr = (void *)(cells + addr_cells);
        switch(size_cells)
        {
        case 0:
            size_buf[i] = 0;
        case 1:
            size_buf[i] = (size_t)fdttoh32(*(fdt32_t *)size_ptr);
            break;
        case 2:
            size_buf[i] = (size_t)fdttoh64(*(fdt64_t *)size_ptr);
            break;
        default:
            return -EINVAL;
        }

        cells += addr_cells + size_cells;
    }

    return 0;
}

static int
dump_fdt_node_fields(printk_f *printer,
                     struct fdt *fdt,
                     struct fdt_node *node,
                     int depth)
{
    int res;

#ifdef PRINT
#undef PRINT
#endif
#define PRINT(...)                                                             \
    do                                                                         \
    {                                                                          \
        for(int i = 0; i < depth; i++)                                         \
        {                                                                      \
            (*printer)("  ");                                                  \
        }                                                                      \
        (*printer)(__VA_ARGS__);                                               \
    } while(0)

    struct fdt_property *prop = fdt_node_first_property(fdt, node);
    while(prop)
    {
        char *prop_name = fdt_property_name(fdt, prop);
        PRINT("%s\n", prop_name);
        prop = fdt_node_next_property(fdt, prop);
    }

    struct fdt_node *subnode = fdt_node_first_subnode(fdt, node);
    while(subnode)
    {
        char *subnode_name = fdt_node_unitname(fdt, subnode);
        PRINT("%s {\n", subnode_name);
        res = dump_fdt_node_fields(printer, fdt, subnode, depth + 1);
        if(res)
        {
            return res;
        }
        PRINT("}\n");
        subnode = fdt_node_next_subnode(fdt, subnode);
    }

    return 0;

#undef PRINT
}

int
dump_fdt(printk_f *printer, struct fdt *fdt)
{
    int res;

    (*printer)("FDT@%p (totalsize=0x%lx) {\n",
               fdt,
               fdttoh32(fdt->hdr.totalsize));
    struct fdt_node *node = fdt_first_node(fdt);
    if(node == NULL)
    {
        (*printer)("ERROR Device Tree Has No Nodes!\n");
        return -EINVAL;
    }

    res = dump_fdt_node_fields(printer, fdt, node, 1);
    if(res)
    {
        (*printer)("\nERROR(%s)\n", errnostr(res));
        (*printer)("}\n");
        return res;
    }

    (*printer)("}\n");

    return 0;
}
