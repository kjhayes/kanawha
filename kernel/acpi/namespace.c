
#include <acpi/namespace.h>

#include <kanawha/kmalloc.h>
#include <kanawha/atomic.h>
#include <kanawha/stddef.h>
#include <kanawha/errno.h>
#include <kanawha/ptree.h>
#include <kanawha/rwlock.h>
#include <kanawha/init.h>

struct acpi_node
{
    atomic_t refcount;

    struct acpi_namespace *ns;

    struct ptree children;
    struct ptree_node child_node;

    struct acpi_node *parent;
    struct acpi_name name;

    rlock_t obj_lock;
    struct acpi_obj *obj;

    unsigned int destroyed : 1;
};

struct acpi_namespace {
    struct acpi_node *root;
    rlock_t lock;
};

static inline struct acpi_node * 
acpi_node_create(
	struct acpi_namespace *ns,
	struct acpi_name *name)
{
    struct acpi_node *node;
    node = kzmalloc(sizeof(*node), KM_KERNEL);
    if(node == NULL) {
	return NULL;
    }

    atomic_set_relaxed(&node->refcount, 1);
    ptree_init(&node->children);

    node->ns = ns;
    node->destroyed = 0;

    node->parent = NULL;
    if(name) {
        node->name = *name;
    } else {
	node->name.raw[0] = 'R';
	node->name.raw[1] = 'O';
	node->name.raw[2] = 'O';
	node->name.raw[3] = 'T';
    }

    rlock_init(&node->obj_lock);
    node->obj = NULL;

    return node;
}

static inline int
__acpi_node_destroy_lockless(
	struct acpi_node *node)
{
    int res;
    node->destroyed = 1;
    struct ptree_node *child_iter = ptree_get_first(&node->children);
    while(child_iter != NULL) {
	struct acpi_node *child = container_of(child_iter, struct acpi_node, child_node);
	DEBUG_ASSERT(child->parent == node);
	__acpi_node_destroy_lockless(child);
	child_iter = ptree_get_next(child_iter);
    }
    if(node->parent) {
	struct ptree_node *removed =
	    ptree_remove(&node->parent->children, node->child_node.key);
	DEBUG_ASSERT(removed == &node->child_node);
	node->parent = NULL;
    }
    acpi_node_put(node);
    return 0;
}
static inline int
acpi_node_destroy(
	struct acpi_node *node)
{
    int res;
    rlock_write_lock(&node->ns->lock);
    res = __acpi_node_destroy_lockless(node);
    rlock_write_unlock(&node->ns->lock);
    return 0;
}

static inline void
acpi_node_deallocate(
	struct acpi_node *node)
{
    DEBUG_ASSERT(node->parent == NULL);
    DEBUG_ASSERT(node->refcount == 0);
    kfree(node);
}

static struct acpi_namespace *
acpi_create_namespace(void)
{
    struct acpi_namespace *ns;
    ns = kzmalloc(sizeof(*ns), KM_KERNEL);
    if(ns == NULL) {
	return NULL;
    }

    rlock_init(&ns->lock);

    ns->root = acpi_node_create(ns, NULL);
    if(ns->root == NULL) {
	kfree(ns);
	return NULL;
    }

    // Bootstrap node -> namespace association
    ns->root->ns = ns;
    
    return ns;
}

static void
acpi_destroy_namespace(
	struct acpi_namespace *ns)
{
    acpi_node_put(ns->root);
    kfree(ns);
}

void
acpi_node_get(
	struct acpi_node *node)
{
    atomic_fetch_inc(&node->refcount);
}

void
acpi_node_put(
	struct acpi_node *node)
{
    atomic_val_t val = atomic_fetch_dec(&node->refcount) - 1;
    if(val == 0) {
	acpi_node_deallocate(node);
    }
}

struct acpi_node *
acpi_node_get_parent(
	struct acpi_node *node)
{
    struct acpi_node *parent;

    rlock_read_lock(&node->ns->lock);

    parent = node->parent;
    if(parent != NULL) {
        acpi_node_get(parent);
    }

    rlock_read_unlock(&node->ns->lock);

    return parent;
}

struct acpi_node *
acpi_namespace_get_root(
	struct acpi_namespace *ns)
{
    acpi_node_get(ns->root);
    return ns->root;
}

struct acpi_node *
acpi_node_lookup_name(
	struct acpi_node *node,
	struct acpi_name *name)
{
    struct acpi_node *child;
    rlock_read_lock(&node->ns->lock);
    struct ptree_node *pnode = ptree_get(&node->children, name->value);
    if(pnode != NULL) {
	child = container_of(pnode, struct acpi_node, child_node);
	acpi_node_get(child);
    } else {
	child = NULL;
    }
    rlock_read_unlock(&node->ns->lock);
    return child;
}

static struct acpi_node *
acpi_node_lookup_ancestor(
	struct acpi_node *scope,
	struct acpi_path *path,
	size_t generations_back)
{
    if(path->prefixes == -1) {
	// Relative to root
	DEBUG_ASSERT(KERNEL_ADDR(scope->ns));
	scope = acpi_namespace_get_root(scope->ns);
    } else {
	int parent_prefixes = path->prefixes;
	acpi_node_get(scope);
	while(parent_prefixes > 0) {
	    struct acpi_node *old = scope;
	    scope = acpi_node_get_parent(scope);
	    acpi_node_put(old);
	    parent_prefixes--;
	}
    }

    // We should have dealt with all prefixes (root/parents)
    // and have an extra reference to scope

    for(size_t i = 0; i < path->pathlen - generations_back; i++)
    {
	struct acpi_node *old = scope;
	scope = acpi_node_lookup_name(scope, &path->names[i]);
	acpi_node_put(old);
	if(scope == NULL) {
	    break;
	}
    }

    return scope;
}

struct acpi_node *
acpi_node_lookup(
	struct acpi_node *scope,
	struct acpi_path *path)
{
    return acpi_node_lookup_ancestor(scope, path, 0);
}

static struct acpi_node *
acpi_node_lookup_parent(
	struct acpi_node *scope,
	struct acpi_path *path)
{
    return acpi_node_lookup_ancestor(scope, path, 1);
}

int
acpi_node_create_named_object(
	struct acpi_node *scope,
	struct acpi_path *path,
	struct acpi_obj *object)
{
    int res;

    if(path->pathlen < 1) {
	return -EINVAL;
    }

    struct acpi_name name = path->names[path->pathlen-1];

    // Gets an extra reference to "parent"
    struct acpi_node *parent = acpi_node_lookup_parent(scope,path);
    if(parent == NULL) {
	return -EINVAL;
    }

    // Returns a child with a single reference
    struct acpi_node *node = acpi_node_create(parent->ns, &name);
    if(node == NULL) {
	acpi_node_put(parent);
	return -EINVAL;
    }

    // We aren't actually in the namespace tree yet so we don't need to lock
    acpi_obj_get(object);
    node->obj = object;

    // We have a reference to both parent and child, so they can't be destroyed from underneath us.
    rlock_write_lock(&parent->ns->lock);
    res = ptree_insert(&parent->children, &node->child_node, node->name.value);
    if(res) {
        rlock_write_unlock(&parent->ns->lock);
	acpi_node_put(node);
	acpi_node_put(parent);
	return res;
    }
    node->parent = parent;
    rlock_write_unlock(&parent->ns->lock);

    acpi_node_put(parent);
    // We don't "put" the child because it is currently on a single reference

    return 0;
}

struct acpi_obj *
acpi_node_get_named_object(
	struct acpi_node *scope,
	struct acpi_path *path)
{
    int res;

    struct acpi_obj *obj;

    struct acpi_node *node = acpi_node_lookup(scope, path);
    if(node == NULL) {
	return NULL;
    }

    rlock_read_lock(&node->obj_lock);

    obj = node->obj;
    if(obj == NULL) {
        rlock_read_unlock(&node->obj_lock);
	return NULL;
    }
    acpi_obj_get(obj);

    rlock_read_unlock(&node->obj_lock);

    acpi_node_put(node);

    return obj;
}


static void
__acpi_namespace_dump_node_lockless(
	struct acpi_node *node,
	printk_f *printer,
	int depth)
{
    for(size_t i = 0; i < depth; i++) {
	(*printer)("  ");
    }
    acpi_dump_name(printer, &node->name);
    rlock_read_lock(&node->obj_lock);
    if(node->obj != NULL) {
        (*printer)(" [");
        acpi_obj_dump(printer, node->obj);
        (*printer)("] ");
    }
    rlock_read_unlock(&node->obj_lock);
    (*printer)("{");
    int num_children = 0;
    struct ptree_node *child_iter;
    child_iter = ptree_get_first(&node->children);
    while(child_iter != NULL) {
	if(num_children == 0) {
	    (*printer)("\n");
	}
	num_children++;
	struct acpi_node *child =
	    container_of(child_iter, struct acpi_node, child_node);
	__acpi_namespace_dump_node_lockless(child, printer, depth+1);
	child_iter = ptree_get_next(child_iter);
    }
    if(num_children > 0) {
        for(size_t i = 0; i < depth; i++) {
            (*printer)("  ");
        }
    }
    (*printer)("}\n");
}

void
acpi_namespace_dump(
	printk_f *printer,
	struct acpi_namespace *ns)
{
    rlock_read_lock(&ns->lock);
    __acpi_namespace_dump_node_lockless(ns->root, printer, 0);
    rlock_read_unlock(&ns->lock);
}

void
acpi_node_dump_path(
	printk_f *printer,
	struct acpi_node *node)
{
    if(node->parent) {
	acpi_node_dump_path(printer, node->parent);
	(*printer)(".");
    } else {
	(*printer)("\\");
    }
    acpi_dump_name(printer, &node->name);
}

struct acpi_name
acpi_node_get_name(
	struct acpi_node *node)
{
    return node->name;
}

static struct acpi_namespace *default_namespace = NULL;

struct acpi_namespace *
acpi_default_namespace(void)
{
    return default_namespace;
}

static int
acpi_namespace_create_predefined_scope(
	struct acpi_namespace *ns,
	const char *name)
{
    int res;

    struct acpi_node *root = acpi_namespace_get_root(ns);

    struct acpi_obj *tmp_obj;
    struct acpi_path *tmp_path = acpi_path_create(1, ACPI_PATH_PREFIX_ROOT);
    if(tmp_path == NULL) {
	return -ENOMEM;
    }

    tmp_path->names[0].value = 0x0;
    strncpy((char*)&tmp_path->names[0].raw, name, 4);
    tmp_obj = acpi_create_scope_obj();
    res = acpi_node_create_named_object(
	    root,
	    tmp_path,
	    tmp_obj);
    if(res) {
	acpi_path_destroy(tmp_path);
	acpi_obj_put(tmp_obj);
	acpi_node_put(root);
	return res;
    }

    acpi_node_put(root);
    acpi_path_destroy(tmp_path);

    return 0;
}

static int
acpi_create_default_namespace(void)
{
    int res;

    struct acpi_namespace *ns;
    ns = acpi_create_namespace();
    if(ns == NULL) {
	return -ENOMEM;
    }

    static const char *predefined_ns[] = {
	"_GPE",
	"_PR_",
	"_SB_",
	"_SI_",
	"_TZ_",
	NULL,
    };

    size_t predefined_ns_index = 0;
    while(predefined_ns[predefined_ns_index] != NULL) {
        res = acpi_namespace_create_predefined_scope(
		ns,
		predefined_ns[predefined_ns_index]);
        if(res) {
            acpi_destroy_namespace(ns);
            return res;
        }
	predefined_ns_index++;
    }

    default_namespace = ns;

    return 0;
}
declare_init_desc(dynamic, acpi_create_default_namespace, "Creating Default ACPI Namespace");

static int
acpi_dump_namespace_on_launch(void) {
    if(default_namespace == NULL) {
	return -EDEFER;
    }
    acpi_namespace_dump(do_printk, default_namespace);
    return 0;
}
declare_init_desc(launch, acpi_dump_namespace_on_launch, "Dumping Default ACPI Namespace");

