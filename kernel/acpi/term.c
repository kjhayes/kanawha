
#include <acpi/term.h>

#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>

struct acpi_termlist *
acpi_create_empty_termlist(void)
{
    struct acpi_termlist *terms =
        kmalloc(sizeof(struct acpi_termlist), KM_KERNEL);
    if(terms == NULL) {
        return NULL;
    }
    memset(terms, 0, sizeof(struct acpi_termlist));

    ilist_init(&terms->terms);

    return terms;
}

int
acpi_destroy_termlist(
        struct acpi_termlist *terms)
{
    int res;

    ilist_node_t *node;
    node = ilist_pop_tail(&terms->terms);
    while(node != NULL) {
        struct acpi_term *term =
            container_of(node, struct acpi_term, list_node);

        res = acpi_destroy_term(term);
        if(res) {
            wprintk("Failed to destroy struct acpi_term!\n");
        }

        node = ilist_pop_tail(&terms->terms);
    }

    kfree(terms);

    return 0;
}


int
acpi_destroy_term(
        struct acpi_term *term)
{
    int res;

    if(term->destroy != NULL) {
        res = (*term->destroy)(term);
        if(res) {
            return res;
        }
    }

    return 0;
}

int
acpi_termlist_append(
        struct acpi_termlist *terms,
        struct acpi_term *term)
{
    ilist_push_tail(&terms->terms, &term->list_node);
    return 0;
}

int
acpi_dump_term(
        struct acpi_term *term,
        printk_f *printer,
        int depth)
{
    if(term->dump == NULL) {
        acpi_dump_term_indent(printer, depth);
        (*printer)("UNKNOWN-TERM(%p)\n",
                (void*)term);
        return -EINVAL;
    } else {
        DEBUG_ASSERT(KERNEL_ADDR(term->dump));
        return (*term->dump)(term, printer, depth);
    }
}


int
acpi_dump_termlist(
        struct acpi_termlist *list,
        printk_f *printer,
        int depth)
{
    acpi_dump_term_indent(printer, depth);
    (*printer)("{\n");

    ilist_node_t *node;
    ilist_for_each(node, &list->terms) {
        struct acpi_term *term = container_of(node, struct acpi_term, list_node);
        acpi_dump_term(
                term,
                printer,
                depth+1);
    }
    acpi_dump_term_indent(printer, depth);
    (*printer)("}\n");

    return 0;
}

